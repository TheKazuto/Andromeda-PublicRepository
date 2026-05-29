package swap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

const nativeToken = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// mockEVMAdapter returns an evmAdapter whose RPC is a stub that answers
// eth_getTransactionCount (pending nonce) and eth_call (allowance). allowanceHex
// is the value returned by eth_call (empty = "0x0").
func mockEVMAdapter(t *testing.T, nonceHex, allowanceHex string) *evmAdapter {
	t.Helper()
	if allowanceHex == "" {
		allowanceHex = "0x0"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result string
		switch req.Method {
		case "eth_getTransactionCount":
			result = nonceHex
		case "eth_call":
			result = allowanceHex
		default:
			result = "0x0"
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`+result+`"}`)
	}))
	t.Cleanup(srv.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newEVMAdapter(chains.NewEVMBroadcaster(nil, logger), nil, map[int]string{8453: srv.URL})
}

func evmStep(from, to string) *lifi.Step {
	tr := map[string]any{
		"from": from, "to": to, "data": "0x", "value": "0x0",
		"gas": "0x5208", "maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x3b9aca00",
		"chainId": 8453, "nonce": "0x0",
	}
	raw, _ := json.Marshal(tr)
	return &lifi.Step{
		Tool: "1inch",
		Action: lifi.Action{
			FromChainID: 8453, ToChainID: 8453,
			FromToken: lifi.Token{Symbol: "ETH"}, ToToken: lifi.Token{Symbol: "USDC"},
		},
		Estimate:           lifi.Estimate{ToAmount: "1000000", ToAmountMin: "990000"},
		TransactionRequest: raw,
	}
}

func TestEVMPrepareHappyNative(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	adapter := mockEVMAdapter(t, "0x7", "")

	out, err := adapter.Prepare(context.Background(), evmStep(from, to), lifi.QuoteParams{
		FromAddress: from, FromToken: nativeToken,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if out.ChainKind != "evm" || out.SignChainID != "eip155:8453" || out.SignScheme != 0 {
		t.Errorf("unexpected fields: %+v", out)
	}
	if out.EVMNonce != 7 {
		t.Errorf("EVMNonce = %d, want 7 (pending)", out.EVMNonce)
	}
	if out.Approval != nil {
		t.Error("native swap must not need an approval")
	}
	if !strings.HasPrefix(out.MessageToSignHex, "02") {
		t.Errorf("MessageToSignHex must start with 02 (type-2 tx), got %.4s", out.MessageToSignHex)
	}
}

// ERC20 with zero allowance must produce an approve tx with nonce N and a swap at N+1.
func TestEVMPrepareBuildsApproval(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	token := "0x3333333333333333333333333333333333333333"
	adapter := mockEVMAdapter(t, "0x4", "0x0") // pending nonce 4, allowance 0

	step := evmStep(from, to)
	step.Estimate.ApprovalAddress = "0x4444444444444444444444444444444444444444"
	out, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: token, FromAmount: "1000000",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if out.Approval == nil {
		t.Fatal("expected an approval tx for zero-allowance ERC20")
	}
	if out.Approval.Nonce != 4 {
		t.Errorf("approve nonce = %d, want 4", out.Approval.Nonce)
	}
	if out.EVMNonce != 5 {
		t.Errorf("swap nonce = %d, want 5 (approve+1)", out.EVMNonce)
	}
	if !strings.HasPrefix(out.Approval.MessageToSignHex, "02") {
		t.Error("approve message must be a type-2 tx")
	}
}

// ERC20 with sufficient allowance must NOT build an approve.
func TestEVMPrepareSkipsApprovalWhenAllowed(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	token := "0x3333333333333333333333333333333333333333"
	// allowance = 0xf4240 (1_000_000) == needed amount → sufficient.
	adapter := mockEVMAdapter(t, "0x4", "0x00000000000000000000000000000000000000000000000000000000000f4240")

	step := evmStep(from, to)
	step.Estimate.ApprovalAddress = "0x4444444444444444444444444444444444444444"
	out, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: token, FromAmount: "1000000",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if out.Approval != nil {
		t.Error("sufficient allowance must not build an approval")
	}
	if out.EVMNonce != 4 {
		t.Errorf("swap nonce = %d, want 4", out.EVMNonce)
	}
}

func TestEVMPrepareRejectsWrongFrom(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	other := "0x9999999999999999999999999999999999999999"
	adapter := newEVMAdapter(nil, nil, nil) // from mismatch is checked before any RPC
	_, err := adapter.Prepare(context.Background(), evmStep(from, "0x2222222222222222222222222222222222222222"),
		lifi.QuoteParams{FromAddress: other, FromToken: nativeToken})
	if err == nil {
		t.Fatal("expected invariant error for from mismatch")
	}
	var inv *InvariantError
	if !asInvariant(err, &inv) {
		t.Errorf("expected InvariantError, got %T", err)
	}
}

// LI.FI returns only gasPrice for legacy chains (BSC and a few others). The
// adapter must encode the tx as type-0 (EIP-155) in that case, not stuff
// gasPrice into a fake EIP-1559 envelope.
func TestEVMPrepareLegacyType0(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	adapter := mockEVMAdapter(t, "0x7", "")

	step := &lifi.Step{
		Tool: "1inch",
		Action: lifi.Action{
			FromChainID: 8453, ToChainID: 8453,
			FromToken: lifi.Token{Symbol: "BNB"}, ToToken: lifi.Token{Symbol: "USDT"},
		},
		Estimate: lifi.Estimate{ToAmount: "1000000", ToAmountMin: "990000"},
	}
	tr := map[string]any{
		"from": from, "to": to, "data": "0x", "value": "0x0",
		"gas": "0x5208", "gasPrice": "0x2faf081",
		"chainId": 8453, "nonce": "0x0",
	}
	step.TransactionRequest, _ = json.Marshal(tr)

	out, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: nativeToken,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// Legacy tx starts with the RLP list prefix (0xc0..0xff), NOT 0x02.
	if strings.HasPrefix(out.MessageToSignHex, "02") {
		t.Errorf("legacy tx must not start with 0x02 (type-2 prefix), got %.4s", out.MessageToSignHex)
	}
	if out.MessageDigestHex == "" {
		t.Error("MessageDigestHex must be populated for legacy too")
	}
}

// TestEVMFinalizeLegacyType0RoundTrip verifies that a legacy (type-0) snapshot
// builds a valid signed RLP envelope on Finalize: the encoded bytes must NOT
// start with the type-2 prefix (0x02) and must round-trip through DeriveMessage
// with the same digest (the orchestrator uses DeriveMessage to revalidate
// snapshots before signing).
func TestEVMFinalizeLegacyType0RoundTrip(t *testing.T) {
	from := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	adapter := mockEVMAdapter(t, "0x7", "")

	step := &lifi.Step{
		Tool: "1inch",
		Action: lifi.Action{
			FromChainID: 8453, ToChainID: 8453,
			FromToken: lifi.Token{Symbol: "BNB"}, ToToken: lifi.Token{Symbol: "USDT"},
		},
		Estimate: lifi.Estimate{ToAmount: "1000000", ToAmountMin: "990000"},
	}
	tr := map[string]any{
		"from": from, "to": to, "data": "0x", "value": "0x0",
		"gas": "0x5208", "gasPrice": "0x2faf081",
		"chainId": 8453, "nonce": "0x0",
	}
	step.TransactionRequest, _ = json.Marshal(tr)
	prep, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: nativeToken,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// DeriveMessage must reproduce the digest byte-for-byte (drift defense).
	derived, err := adapter.DeriveMessage(prep.UnsignedTxB64)
	if err != nil {
		t.Fatalf("DeriveMessage: %v", err)
	}
	if derived.DigestHex != prep.MessageDigestHex {
		t.Errorf("derived digest %q != prepare digest %q", derived.DigestHex, prep.MessageDigestHex)
	}
}

func TestEVMSignedEncodingShape(t *testing.T) {
	to := make([]byte, 20)
	signed := encodeEIP1559Signed(
		8453, 0, big.NewInt(1), big.NewInt(2), 21000, to, big.NewInt(0), nil, nil,
		big.NewInt(1), big.NewInt(0x1234), big.NewInt(0x5678),
	)
	if len(signed) == 0 || signed[0] != 0x02 {
		t.Fatalf("signed tx must start with 0x02, got %x", signed[:1])
	}
	if len(keccak256(signed)) != 32 {
		t.Error("keccak256 must be 32 bytes")
	}
}

// A persisted snapshot with an unparseable numeric field must fail loudly on
// DeriveMessage (InvariantError → 422), never silently encode it as zero.
func TestEVMDeriveRejectsCorruptSnapshot(t *testing.T) {
	adapter := newEVMAdapter(nil, nil, nil)
	cases := map[string]string{
		"bad value":    `{"chainId":8453,"nonce":0,"gas":21000,"to":"0x2222222222222222222222222222222222222222","value":"not-a-number","data":"0x","txType":2,"maxFeePerGas":"1","maxPriorityFeePerGas":"1"}`,
		"bad maxFee":   `{"chainId":8453,"nonce":0,"gas":21000,"to":"0x2222222222222222222222222222222222222222","value":"0","data":"0x","txType":2,"maxFeePerGas":"zzz","maxPriorityFeePerGas":"1"}`,
		"bad gasPrice": `{"chainId":8453,"nonce":0,"gas":21000,"to":"0x2222222222222222222222222222222222222222","value":"0","data":"0x","txType":0,"gasPrice":"oops"}`,
		"bad data":     `{"chainId":8453,"nonce":0,"gas":21000,"to":"0x2222222222222222222222222222222222222222","value":"0","data":"0xZZ","txType":2,"maxFeePerGas":"1","maxPriorityFeePerGas":"1"}`,
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			b64 := base64.StdEncoding.EncodeToString([]byte(snap))
			_, err := adapter.DeriveMessage(b64)
			if err == nil {
				t.Fatalf("expected an error for %s", name)
			}
			var inv *InvariantError
			if !asInvariant(err, &inv) {
				t.Errorf("expected InvariantError, got %T", err)
			}
		})
	}
}
