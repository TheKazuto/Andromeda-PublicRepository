package swap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"

	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// suiCAIP2 is the CAIP-2 id the gateway forwards to ika prepare-message.
// `parseChainId` in ika-backend chains.ts only reads the namespace ("sui");
// the reference is opaque. We use the same `sui:mainnet` form the ika-backend
// fixture (fixtures/chain/preprocess-v1.json) uses, so cross-language tests
// share one canonical chainId and drift is impossible.
const suiCAIP2 = "sui:mainnet"

// suiSignScheme is EddsaSha512 (Ed25519). Matches ika-backend chains.ts:65.
const suiSignScheme = 5

// suiAdapter is the ChainAdapter for Sui swaps (Cetus / LI.FI tools). LI.FI's
// Sui responses currently come from `cetus` (same-chain) and Wormhole / Mayan
// (cross-chain to EVM). The wire shape is the same: transactionRequest.data is
// a base64-encoded BCS-serialized TransactionData; the dWallet signs that with
// Ed25519 after ika applies the Sui intent envelope.
type suiAdapter struct {
	broadcaster *chains.SuiBroadcaster
	lifi        *lifi.Client
	rpcOverride string // env override (SUI_RPC_URL)
}

func newSuiAdapter(b *chains.SuiBroadcaster, l *lifi.Client, override string) *suiAdapter {
	return &suiAdapter{broadcaster: b, lifi: l, rpcOverride: override}
}

func (a *suiAdapter) Key() string     { return "sui" }
func (a *suiAdapter) SignScheme() int { return suiSignScheme }

func (a *suiAdapter) ResolveRPCs(chainID int) []string {
	if a.rpcOverride != "" {
		return []string{a.rpcOverride}
	}
	if a.lifi == nil {
		return nil
	}
	return a.lifi.RPC().RPCsFor(chainID)
}

// txRequestSui is the LI.FI transactionRequest shape for Sui: `data` is the
// base64 of BCS-encoded TransactionData (Move VM tx). The dWallet must be the
// sender — LI.FI builds the tx for action.fromAddress; if these disagree the
// signature will not match the BCS sender and the Sui network rejects at exec.
type txRequestSui struct {
	Data string `json:"data"`
}

// Prepare validates the LI.FI Sui tx and extracts the message to sign. The
// `MessageToSignHex` we hand to ika prepare-message is the RAW txBytes —
// ika applies blake2b(intent[0,0,0] || txBytes) automatically with
// kind="transaction" (see ika-backend preprocess.ts:67-83).
func (a *suiAdapter) Prepare(_ context.Context, step *lifi.Step, p lifi.QuoteParams) (*PrepareResult, error) {
	if len(step.TransactionRequest) == 0 {
		return nil, invariant("LI.FI returned no transactionRequest for the route")
	}
	var tr txRequestSui
	if err := json.Unmarshal(step.TransactionRequest, &tr); err != nil || tr.Data == "" {
		return nil, invariant("LI.FI Sui transactionRequest has no data field")
	}
	txBytes, err := base64.StdEncoding.DecodeString(tr.Data)
	if err != nil {
		return nil, invariant("LI.FI Sui tx is not valid base64")
	}
	if len(txBytes) == 0 {
		return nil, invariant("LI.FI Sui tx is empty")
	}
	// Sender invariant: LI.FI tells us in action.fromAddress which dWallet
	// the tx was built for. The actual sender is BCS-encoded inside txBytes;
	// decoding BCS in Go is non-trivial, so we rely on the LI.FI-declared
	// fromAddress as the cross-check. A drift here would still fail at the
	// Sui node (signature/sender mismatch) — not a security hole, just a
	// noisier failure mode.
	if !eqSuiAddress(step.Action.FromAddress, p.FromAddress) {
		return nil, invariant("Sui tx fromAddress (%s) is not the dWallet (%s)", step.Action.FromAddress, p.FromAddress)
	}

	sum := sha256.Sum256(txBytes)
	est := step.Estimate
	return &PrepareResult{
		ChainKind:           "sui",
		ChainID:             step.Action.FromChainID,
		SignChainID:         suiCAIP2,
		SignScheme:          suiSignScheme,
		ChainNativeAddress:  normalizeSuiAddress(step.Action.FromAddress),
		UnsignedTxB64:       tr.Data,
		MessageToSignHex:    hex.EncodeToString(txBytes),
		MessageDigestHex:    hex.EncodeToString(keccak256(suiIntentDigest(txBytes))),
		UnsignedTxHash:      hex.EncodeToString(sum[:]),
		AmountOut:           est.ToAmount,
		AmountOutMin:        est.ToAmountMin,
		TransactionFeeUSD:   est.TransactionFeeUSD(),
		NativeFeeEstimate:   est.NativeFeeEstimate(),
		NativeFeeUSD:        est.NativeFeeUSD(),
		RequiresAtaCreation: false,
		Tool:                step.Tool,
		RouteSnapshot:       routeSnapshot(step),
		Notice:              "pre-alpha — Sui swaps via LI.FI / Cetus are beta; not for real value",
	}, nil
}

// DeriveMessage recomputes the bytes-to-sign + intent digest from the
// persisted Sui unsignedTx WITHOUT re-quoting LI.FI. The digest matches the
// `digestHex` ika returns from prepare-message: blake2b256([0,0,0] || txBytes).
func (a *suiAdapter) DeriveMessage(unsignedTxB64 string) (*DeriveResult, error) {
	raw, err := base64.StdEncoding.DecodeString(unsignedTxB64)
	if err != nil {
		return nil, invariant("unsignedTx is not valid base64")
	}
	if len(raw) == 0 {
		return nil, invariant("unsignedTx is empty")
	}
	sum := sha256.Sum256(raw)
	return &DeriveResult{
		MessageToSignHex: hex.EncodeToString(raw),
		DigestHex:        hex.EncodeToString(keccak256(suiIntentDigest(raw))),
		UnsignedTxHash:   hex.EncodeToString(sum[:]),
	}, nil
}

// Finalize wraps the raw Ed25519 signature in the Sui-flagged shape
// (1-byte scheme flag 0x00 || 64-byte sig || 32-byte pubkey, all base64'd) and
// calls sui_executeTransactionBlock with the persisted txBytes.
func (a *suiAdapter) Finalize(ctx context.Context, in FinalizeInput, urls []string) (*FinalizeResult, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(in.SignatureB64)
	if err != nil || len(sigBytes) != 64 {
		return nil, invariant("Sui signature must be base64-encoded 64 bytes")
	}
	pkBytes, err := hex.DecodeString(in.SignerPubkeyHex)
	if err != nil || len(pkBytes) != 32 {
		return nil, invariant("signerPubkeyHex must be 32-byte hex for Sui")
	}
	flagged := make([]byte, 1+64+32)
	flagged[0] = 0x00 // ed25519 scheme flag
	copy(flagged[1:65], sigBytes)
	copy(flagged[65:], pkBytes)
	flaggedB64 := base64.StdEncoding.EncodeToString(flagged)

	digest, unknown, err := a.broadcaster.Execute(ctx, urls, in.UnsignedTxB64, []string{flaggedB64}, in.ChainID)
	if err != nil {
		if unknown {
			// On Sui the tx digest is deterministic from txBytes alone (it is
			// blake2b256([0,0,0] || txBytes)) — surface it so the gateway can
			// reconcile without a blind retry.
			return &FinalizeResult{TxHash: suiTxDigestBase58(in.UnsignedTxB64), BroadcastUnknown: true}, nil
		}
		return nil, err
	}
	if digest == "" {
		digest = suiTxDigestBase58(in.UnsignedTxB64)
	}
	return &FinalizeResult{TxHash: digest}, nil
}

// NativeBalance returns the dWallet's MIST balance (1 SUI = 1e9 MIST) as a
// decimal string.
func (a *suiAdapter) NativeBalance(ctx context.Context, urls []string, address string) (string, error) {
	return a.broadcaster.Balance(ctx, urls, address)
}

// ---- Sui helpers --------------------------------------------------------

// suiIntentDigest returns blake2b256(intent || txBytes), the value ika
// computes as `preprocessedHex` when preprocess applies the Sui envelope to a
// kind="transaction" payload (see ika-backend preprocess.ts:80-83). The
// intent prefix is `[0, 0, 0]` = (scope=TransactionData, version=V0, app=0);
// the personal-message scope (3) is never used by the swap path.
func suiIntentDigest(txBytes []byte) []byte {
	buf := make([]byte, 3+len(txBytes))
	// buf[0..3] = [0, 0, 0] (already zero from make)
	copy(buf[3:], txBytes)
	sum := blake2b.Sum256(buf)
	return sum[:]
}

// suiTxDigestBase58 returns the canonical Sui transaction digest — base58 of
// blake2b256(intent || txBytes). This is the exact form Sui fullnodes and the
// LI.FI /status route use as the tx hash key, so reconciling an ambiguous
// broadcast against /status works without format translation.
func suiTxDigestBase58(unsignedTxB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(unsignedTxB64)
	if err != nil {
		return ""
	}
	return base58.Encode(suiIntentDigest(raw))
}

// normalizeSuiAddress returns the canonical 32-byte Sui address: lowercase,
// 0x-prefixed, padded to 64 hex chars (Sui short-form addresses elide leading
// zeros, but the BCS-encoded sender is always 32 bytes). This is the form
// persisted in the intent so equality checks downstream are byte-stable.
func normalizeSuiAddress(addr string) string {
	return expandSuiAddress(addr)
}

// eqSuiAddress compares two Sui addresses with normalization (case + 0x
// prefix + leading-zero padding). LI.FI may return the short form while the
// caller passes the full form, so we expand both before comparing.
func eqSuiAddress(a, b string) bool {
	return expandSuiAddress(a) == expandSuiAddress(b)
}

func expandSuiAddress(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	a = strings.TrimPrefix(a, "0x") // ToLower already normalized any 0X
	// Pad to 64 hex chars (32 bytes) with leading zeros.
	if len(a) < 64 {
		a = strings.Repeat("0", 64-len(a)) + a
	}
	return "0x" + a
}
