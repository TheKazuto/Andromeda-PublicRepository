package swap

import (
	"context"
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

// mockEVMService returns a swap.Service whose EVM RPC is a stub that answers
// eth_getTransactionCount (pending nonce) and eth_call (allowance). allowanceHex
// is the value returned by eth_call (empty = "0x0").
func mockEVMService(t *testing.T, nonceHex, allowanceHex string) *Service {
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
	return &Service{
		evm:          chains.NewEVMBroadcaster(nil, logger),
		evmOverrides: map[int]string{8453: srv.URL},
		logger:       logger,
	}
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
	svc := mockEVMService(t, "0x7", "")

	out, err := svc.evmPrepare(context.Background(), evmStep(from, to), lifi.QuoteParams{
		FromAddress: from, FromToken: nativeToken,
	})
	if err != nil {
		t.Fatalf("evmPrepare: %v", err)
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
	svc := mockEVMService(t, "0x4", "0x0") // pending nonce 4, allowance 0

	step := evmStep(from, to)
	step.Estimate.ApprovalAddress = "0x4444444444444444444444444444444444444444"
	out, err := svc.evmPrepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: token, FromAmount: "1000000",
	})
	if err != nil {
		t.Fatalf("evmPrepare: %v", err)
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
	svc := mockEVMService(t, "0x4", "0x00000000000000000000000000000000000000000000000000000000000f4240")

	step := evmStep(from, to)
	step.Estimate.ApprovalAddress = "0x4444444444444444444444444444444444444444"
	out, err := svc.evmPrepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: from, FromToken: token, FromAmount: "1000000",
	})
	if err != nil {
		t.Fatalf("evmPrepare: %v", err)
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
	svc := &Service{} // from mismatch is checked before any RPC
	_, err := svc.evmPrepare(context.Background(), evmStep(from, "0x2222222222222222222222222222222222222222"),
		lifi.QuoteParams{FromAddress: other, FromToken: nativeToken})
	if err == nil {
		t.Fatal("expected invariant error for from mismatch")
	}
	var inv *InvariantError
	if !asInvariant(err, &inv) {
		t.Errorf("expected InvariantError, got %T", err)
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
