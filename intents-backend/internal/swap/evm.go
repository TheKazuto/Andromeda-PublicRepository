package swap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// nativeSentinels are the addresses LI.FI uses for a chain's native token (no
// ERC20 allowance ever needed for these).
var nativeSentinels = map[string]bool{
	"0x0000000000000000000000000000000000000000": true,
	"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": true,
}

// txRequestEVM is the LI.FI transactionRequest for EVM. Numeric fields arrive as
// hex strings ("0x..") or decimal; chainId/nonce can be number or hex string.
type txRequestEVM struct {
	From                 string          `json:"from"`
	To                   string          `json:"to"`
	Data                 string          `json:"data"`
	Value                string          `json:"value"`
	Gas                  string          `json:"gas"`
	GasLimit             string          `json:"gasLimit"`
	GasPrice             string          `json:"gasPrice"`
	MaxFeePerGas         string          `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string          `json:"maxPriorityFeePerGas"`
	ChainID              json.RawMessage `json:"chainId"`
	Nonce                json.RawMessage `json:"nonce"`
}

// evmTx is the persisted snapshot (base64 JSON in unsigned_tx). Big values are
// decimal strings so finalize reassembles the exact same signed tx.
type evmTx struct {
	ChainID        uint64 `json:"chainId"`
	Nonce          uint64 `json:"nonce"`
	MaxPriorityFee string `json:"maxPriorityFeePerGas"`
	MaxFee         string `json:"maxFeePerGas"`
	Gas            uint64 `json:"gas"`
	To             string `json:"to"`
	Value          string `json:"value"`
	Data           string `json:"data"`
}

// erc20AllowanceSelector = keccak256("allowance(address,address)")[:4].
var erc20AllowanceSelector = []byte{0xdd, 0x62, 0xed, 0x3e}

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// evmPrepare validates the LI.FI EVM tx, enforces invariants (from == dWallet,
// no ERC20 approval gap), and builds the EIP-1559 signing payload.
func (s *Service) evmPrepare(ctx context.Context, step *lifi.Step, p lifi.QuoteParams) (*PrepareResult, error) {
	if len(step.TransactionRequest) == 0 {
		return nil, invariant("LI.FI returned no transactionRequest for the route")
	}
	var tr txRequestEVM
	if err := json.Unmarshal(step.TransactionRequest, &tr); err != nil {
		return nil, invariant("LI.FI EVM transactionRequest is unreadable")
	}
	if !eqAddr(tr.From, p.FromAddress) {
		return nil, invariant("EVM tx `from` (%s) is not the dWallet (%s)", tr.From, p.FromAddress)
	}
	if tr.To == "" {
		return nil, invariant("EVM tx has no `to` (contract creation is not a swap)")
	}
	toBytes, err := hexAddr(tr.To)
	if err != nil {
		return nil, invariant("EVM tx `to` is not a 20-byte address")
	}

	chainID, err := parseFlexUint(tr.ChainID)
	if err != nil {
		return nil, invariant("EVM tx chainId is invalid")
	}

	maxFee := firstNonZero(tr.MaxFeePerGas, tr.GasPrice)
	maxPriority := firstNonZero(tr.MaxPriorityFeePerGas, tr.GasPrice)
	maxFeeBig, err := parseBig(maxFee)
	if err != nil {
		return nil, invariant("EVM tx fee fields are invalid")
	}
	maxPriorityBig, err := parseBig(maxPriority)
	if err != nil {
		return nil, invariant("EVM tx priority fee is invalid")
	}
	gasBig, err := parseBig(firstNonZero(tr.Gas, tr.GasLimit))
	if err != nil || gasBig.Sign() == 0 {
		return nil, invariant("EVM tx gas is missing")
	}
	valueBig, _ := parseBig(tr.Value)
	dataBytes, err := hexBytes(tr.Data)
	if err != nil {
		return nil, invariant("EVM tx data is not valid hex")
	}

	// Nonce: always use the chain's pending nonce. We override LI.FI's quote-time
	// nonce because it can be stale and, with a two-step approve, the swap must
	// sit one above the approve. The gateway enforces a single in-flight EVM swap
	// per (dwallet, chain), so the pending nonce never collides with our own txs.
	urls := s.resolveEVMRPCs(int(chainID))
	if len(urls) == 0 {
		return nil, invariant("no EVM RPC available for chain %d to assign a nonce (set EVM_RPC_URLS_JSON or wait for /chains)", chainID)
	}
	baseNonce, err := s.evm.PendingNonce(ctx, urls, tr.From)
	if err != nil {
		return nil, fmt.Errorf("fetch nonce: %w", err)
	}

	// ERC20 allowance: if the input is an ERC20 with an insufficient allowance for
	// the named spender, build an approve tx to run BEFORE the swap (two-step).
	// The approve takes baseNonce; the swap moves to baseNonce+1. Native tokens
	// and already-approved ERC20s skip this and the swap keeps baseNonce.
	var approval *EVMApproval
	swapNonce := baseNonce
	if allowance, spender, checked := s.evmAllowance(ctx, p, tr.From, step.Estimate.ApprovalAddress, urls); checked {
		need, ok := new(big.Int).SetString(p.FromAmount, 10)
		if ok && allowance.Cmp(need) < 0 {
			approval = buildApprove(chainID, baseNonce, p.FromToken, spender, need, maxPriorityBig, maxFeeBig)
			swapNonce = baseNonce + 1
		}
	}

	// EIP-1559 unsigned signing payload: 0x02 || rlp([chainId, nonce,
	// maxPriorityFee, maxFee, gas, to, value, data, accessList]).
	unsigned := encodeEIP1559(chainID, swapNonce, maxPriorityBig, maxFeeBig, gasBig.Uint64(), toBytes, valueBig, dataBytes, nil)

	snap := evmTx{
		ChainID: chainID, Nonce: swapNonce,
		MaxPriorityFee: maxPriorityBig.String(), MaxFee: maxFeeBig.String(),
		Gas: gasBig.Uint64(), To: strings.ToLower(tr.To), Value: valueBig.String(),
		Data: "0x" + hex.EncodeToString(dataBytes),
	}
	snapJSON, _ := json.Marshal(snap)
	sum := sha256.Sum256(snapJSON)

	est := step.Estimate
	return &PrepareResult{
		ChainKind:           "evm",
		ChainID:             int(chainID),
		SignChainID:         fmt.Sprintf("eip155:%d", chainID),
		SignScheme:          0, // EcdsaKeccak256
		ChainNativeAddress:  strings.ToLower(tr.From),
		UnsignedTxB64:       base64.StdEncoding.EncodeToString(snapJSON),
		MessageToSignHex:    hex.EncodeToString(unsigned),
		UnsignedTxHash:      hex.EncodeToString(sum[:]),
		AmountOut:           est.ToAmount,
		AmountOutMin:        est.ToAmountMin,
		TransactionFeeUSD:   est.TransactionFeeUSD(),
		NativeFeeEstimate:   est.NativeFeeEstimate(),
		NativeFeeUSD:        est.NativeFeeUSD(),
		RequiresAtaCreation: false,
		Tool:                step.Tool,
		RouteSnapshot:       routeSnapshot(step),
		Notice:              "pre-alpha / devnet — not for real value",
		EVMNonce:            swapNonce,
		Approval:            approval,
	}, nil
}

// EVMApproval is an ERC20 approve tx the gateway must run before the swap.
type EVMApproval struct {
	UnsignedTxB64    string `json:"unsignedTxB64"`
	MessageToSignHex string `json:"messageToSignHex"`
	Token            string `json:"token"`
	Spender          string `json:"spender"`
	Nonce            uint64 `json:"nonce"`
}

// approveGas is a generous fixed limit for a standard ERC20 approve (~46k).
const approveGas = 100000

// erc20ApproveSelector = keccak256("approve(address,uint256)")[:4].
var erc20ApproveSelector = []byte{0x09, 0x5e, 0xa7, 0xb3}

// buildApprove constructs an EIP-1559 ERC20 approve(spender, amount) tx.
func buildApprove(chainID, nonce uint64, token, spender string, amount, maxPriority, maxFee *big.Int) *EVMApproval {
	tokenBytes, _ := hexAddr(token)
	spenderBytes, _ := hexAddr(spender)
	data := make([]byte, 0, 4+64)
	data = append(data, erc20ApproveSelector...)
	data = append(data, leftPad32(spenderBytes)...)
	data = append(data, leftPad32(amount.Bytes())...)

	unsigned := encodeEIP1559(chainID, nonce, maxPriority, maxFee, approveGas, tokenBytes, new(big.Int), data, nil)
	snap := evmTx{
		ChainID: chainID, Nonce: nonce,
		MaxPriorityFee: maxPriority.String(), MaxFee: maxFee.String(),
		Gas: approveGas, To: strings.ToLower(token), Value: "0",
		Data: "0x" + hex.EncodeToString(data),
	}
	snapJSON, _ := json.Marshal(snap)
	return &EVMApproval{
		UnsignedTxB64:    base64.StdEncoding.EncodeToString(snapJSON),
		MessageToSignHex: hex.EncodeToString(unsigned),
		Token:            strings.ToLower(token),
		Spender:          strings.ToLower(spender),
		Nonce:            nonce,
	}
}

// EVMReceipt reports whether an EVM tx is mined (found) and succeeded. Used by
// the gateway to gate the swap on the ERC20 approve confirming.
func (s *Service) EVMReceipt(ctx context.Context, chainID int, txHash string) (bool, bool, error) {
	urls := s.resolveEVMRPCs(chainID)
	if len(urls) == 0 {
		return false, false, fmt.Errorf("no EVM RPC available for chain %d", chainID)
	}
	return s.evm.TransactionReceipt(ctx, urls, txHash)
}

// evmFinalize appends the ECDSA signature (r||s||v, v = yParity) and broadcasts.
func (s *Service) evmFinalize(ctx context.Context, in FinalizeInput, urls []string) (*FinalizeResult, error) {
	var snap evmTx
	raw, err := base64.StdEncoding.DecodeString(in.UnsignedTxB64)
	if err != nil {
		return nil, invariant("unsignedTx is not valid base64")
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, invariant("unsignedTx snapshot is unreadable")
	}
	sig, err := base64.StdEncoding.DecodeString(in.SignatureB64)
	if err != nil || len(sig) != 65 {
		return nil, invariant("EVM signature must be base64-encoded 65 bytes (r||s||v)")
	}
	r := new(big.Int).SetBytes(sig[0:32])
	sVal := new(big.Int).SetBytes(sig[32:64])
	yParity := big.NewInt(int64(sig[64] & 0x01))

	toBytes, err := hexAddr(snap.To)
	if err != nil {
		return nil, invariant("snapshot `to` is invalid")
	}
	value, _ := parseBig(snap.Value)
	maxFee, _ := parseBig(snap.MaxFee)
	maxPriority, _ := parseBig(snap.MaxPriorityFee)
	data, _ := hexBytes(snap.Data)

	signed := encodeEIP1559Signed(snap.ChainID, snap.Nonce, maxPriority, maxFee, snap.Gas, toBytes, value, data, nil, yParity, r, sVal)
	txHash := "0x" + hex.EncodeToString(keccak256(signed))

	hash, unknown, err := s.evm.SendRawTransaction(ctx, urls, signed, txHash, in.ChainID)
	if err != nil {
		if unknown {
			return &FinalizeResult{TxHash: txHash, BroadcastUnknown: true}, nil
		}
		return nil, fmt.Errorf("broadcast failed: %w", err)
	}
	if hash == "" {
		hash = txHash
	}
	return &FinalizeResult{TxHash: hash}, nil
}

// evmAllowance reads the ERC20 allowance(owner, spender) on-chain. checked=false
// for native tokens, a missing spender, or an RPC failure (the caller then skips
// the approve and lets any real revert surface at broadcast). Returns the
// current allowance + the spender when checked.
func (s *Service) evmAllowance(ctx context.Context, p lifi.QuoteParams, owner, spender string, urls []string) (*big.Int, string, bool) {
	token := strings.ToLower(p.FromToken)
	if spender == "" || nativeSentinels[token] || !strings.HasPrefix(token, "0x") || len(token) != 42 {
		return nil, "", false
	}
	ownerB, err1 := hexAddr(owner)
	spenderB, err2 := hexAddr(spender)
	if err1 != nil || err2 != nil {
		return nil, "", false
	}
	data := make([]byte, 0, 4+64)
	data = append(data, erc20AllowanceSelector...)
	data = append(data, leftPad32(ownerB)...)
	data = append(data, leftPad32(spenderB)...)

	res, err := s.evm.EthCall(ctx, urls, p.FromToken, data)
	if err != nil || len(res) == 0 {
		return nil, "", false
	}
	return new(big.Int).SetBytes(res), spender, true
}

// ---- EIP-1559 encoding helpers ----

func encodeEIP1559(chainID, nonce uint64, maxPriority, maxFee *big.Int, gas uint64, to []byte, value *big.Int, data, accessList []byte) []byte {
	items := eip1559Fields(chainID, nonce, maxPriority, maxFee, gas, to, value, data)
	return append([]byte{0x02}, rlpList(items...)...)
}

func encodeEIP1559Signed(chainID, nonce uint64, maxPriority, maxFee *big.Int, gas uint64, to []byte, value *big.Int, data, accessList []byte, yParity, r, sVal *big.Int) []byte {
	items := eip1559Fields(chainID, nonce, maxPriority, maxFee, gas, to, value, data)
	items = append(items, rlpUint(yParity), rlpUint(r), rlpUint(sVal))
	return append([]byte{0x02}, rlpList(items...)...)
}

func eip1559Fields(chainID, nonce uint64, maxPriority, maxFee *big.Int, gas uint64, to []byte, value *big.Int, data []byte) [][]byte {
	return [][]byte{
		rlpUint(new(big.Int).SetUint64(chainID)),
		rlpUint(new(big.Int).SetUint64(nonce)),
		rlpUint(maxPriority),
		rlpUint(maxFee),
		rlpUint(new(big.Int).SetUint64(gas)),
		rlpString(to),
		rlpUint(value),
		rlpString(data),
		rlpList(), // empty accessList
	}
}

// ---- parsing helpers ----

func eqAddr(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func hexAddr(s string) ([]byte, error) {
	b, err := hexBytes(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("address must be 20 bytes, got %d", len(b))
	}
	return b, nil
}

func hexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func firstNonZero(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseBig parses a hex ("0x..") or decimal string into a big.Int. Empty = 0.
func parseBig(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return new(big.Int), nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex %q", s)
		}
		return n, nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal %q", s)
	}
	return n, nil
}

// parseFlexUint parses a JSON number or quoted hex/decimal string into a uint64.
func parseFlexUint(raw json.RawMessage) (uint64, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, fmt.Errorf("empty")
	}
	s = strings.Trim(s, `"`)
	n, err := parseBig(s)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}
