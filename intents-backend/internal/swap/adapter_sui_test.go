package swap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// suiFixturePayload is the txBytes from fixtures/chain/preprocess-v1.json
// (chainId=sui:mainnet, kind=transaction). The fixture is shared with the
// ika-backend preprocess tests — if either side drifts, this test fails and
// the cross-language invariant is restored before merge.
const (
	suiFixturePayloadHex      = "000002000800ca9a3b00000000"
	suiFixturePreprocessedHex = "285018ba70101462ddd753309145a8e4c86a4b3e9e7749effc15f9a88763894c"
	suiFixtureDigestHex       = "8ba44f1234d3cd792f5be268c89ea7b987a8e93f63417b7681417d11b31b9a3b"
)

// TestSuiEnvelopeMatchesIkaFixture pins the Sui intent envelope:
// blake2b256([0,0,0] || txBytes) MUST equal the `preprocessedHex` ika returns
// for the same payload. This is the cross-language fixture that protects
// against silent drift between intents-backend (Go) and ika-backend
// (TypeScript preprocess.ts:67-83).
func TestSuiEnvelopeMatchesIkaFixture(t *testing.T) {
	txBytes, err := hex.DecodeString(suiFixturePayloadHex)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	got := suiIntentDigest(txBytes)
	want, _ := hex.DecodeString(suiFixturePreprocessedHex)
	if hex.EncodeToString(got) != suiFixturePreprocessedHex {
		t.Errorf("suiIntentDigest:\n  got  = %x\n  want = %s (ika preprocessedHex)", got, want)
	}
}

// TestSuiAdapterDigestMatchesIkaFixture pins the message digest:
// keccak256(blake2b(intent || txBytes)) MUST equal the `digestHex` ika returns.
// This is the value the gateway uses for the on-chain MessageApproval PDA, so
// drift would mean the on-chain authorization key disagrees with what was
// actually signed — a CRITICAL security invariant.
func TestSuiAdapterDigestMatchesIkaFixture(t *testing.T) {
	txBytes, err := hex.DecodeString(suiFixturePayloadHex)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	got := keccak256(suiIntentDigest(txBytes))
	if hex.EncodeToString(got) != suiFixtureDigestHex {
		t.Errorf("digest:\n  got  = %x\n  want = %s (ika digestHex)", got, suiFixtureDigestHex)
	}
}

func TestSuiPrepareHappyPath(t *testing.T) {
	txBytes, _ := hex.DecodeString(suiFixturePayloadHex)
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	sender := "0x0000000000000000000000000000000000000000000000000000000000000001"
	step := &lifi.Step{
		Tool: "cetus",
		Action: lifi.Action{
			FromChainID: 9270000000000000,
			ToChainID:   9270000000000000,
			FromAddress: sender,
			FromToken:   lifi.Token{Symbol: "SUI"},
			ToToken:     lifi.Token{Symbol: "USDC"},
		},
		Estimate:           lifi.Estimate{ToAmount: "996929", ToAmountMin: "991944"},
		TransactionRequest: json.RawMessage(`{"data":"` + txB64 + `"}`),
	}
	adapter := newSuiAdapter(nil, nil, "")

	out, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{FromAddress: sender})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if out.ChainKind != "sui" || out.SignChainID != suiCAIP2 || out.SignScheme != suiSignScheme {
		t.Errorf("unexpected fields: %+v", out)
	}
	if out.MessageToSignHex != suiFixturePayloadHex {
		t.Errorf("MessageToSignHex = %q, want %q", out.MessageToSignHex, suiFixturePayloadHex)
	}
	if out.MessageDigestHex != suiFixtureDigestHex {
		t.Errorf("MessageDigestHex = %q, want %q (ika fixture)", out.MessageDigestHex, suiFixtureDigestHex)
	}
	if out.UnsignedTxB64 != txB64 {
		t.Error("UnsignedTxB64 must equal the LI.FI snapshot")
	}
}

func TestSuiPrepareRejectsSenderDrift(t *testing.T) {
	txBytes, _ := hex.DecodeString(suiFixturePayloadHex)
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	step := &lifi.Step{
		Action: lifi.Action{
			FromChainID: 9270000000000000,
			FromAddress: "0x0000000000000000000000000000000000000000000000000000000000000001",
		},
		TransactionRequest: json.RawMessage(`{"data":"` + txB64 + `"}`),
	}
	adapter := newSuiAdapter(nil, nil, "")

	// dWallet says sender is 0x...02 but LI.FI built tx for 0x...01 — must reject.
	_, err := adapter.Prepare(context.Background(), step, lifi.QuoteParams{
		FromAddress: "0x0000000000000000000000000000000000000000000000000000000000000002",
	})
	if err == nil {
		t.Fatal("expected invariant error for sender mismatch")
	}
	var inv *InvariantError
	if !asInvariant(err, &inv) {
		t.Errorf("expected InvariantError, got %T", err)
	}
}

// TestSuiAddressExpansion verifies the short-form ↔ full-form normalization
// the adapter does on Sui addresses (Sui canonical is 32 bytes but the RPC
// may return short form with leading zeros elided).
func TestSuiAddressExpansion(t *testing.T) {
	short := "0x1"
	full := "0x0000000000000000000000000000000000000000000000000000000000000001"
	if !eqSuiAddress(short, full) {
		t.Errorf("eqSuiAddress(%q, %q) = false, want true", short, full)
	}
	if !eqSuiAddress(strings.ToUpper(short), full) {
		t.Errorf("case-insensitive comparison failed")
	}
}
