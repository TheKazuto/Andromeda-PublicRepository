package swap

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"

	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// buildSolanaTxB64 builds a minimal real Solana transfer tx with feePayer as the
// sole signer and returns its base64 serialization.
func buildSolanaTxB64(t *testing.T, feePayer solana.PublicKey) string {
	t.Helper()
	to := solana.NewWallet().PublicKey()
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(1, feePayer, to).Build(),
		},
		solana.Hash{}, // zero blockhash — fine for a serialization-only test
		solana.TransactionPayer(feePayer),
	)
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func stepFor(b64 string, payer solana.PublicKey) *lifi.Step {
	return &lifi.Step{
		Tool: "jupiter",
		Action: lifi.Action{
			FromChainID: 1151111081099710,
			ToChainID:   1151111081099710,
			FromToken:   lifi.Token{Symbol: "USDC", Address: payer.String()},
			ToToken:     lifi.Token{Symbol: "SOL"},
		},
		Estimate: lifi.Estimate{
			ToAmount:    "5000000",
			ToAmountMin: "4950000",
			GasCosts:    []lifi.CostItem{{Name: "gas", Amount: "5000", AmountUSD: "0.01"}},
		},
		TransactionRequest: json.RawMessage(`{"data":"` + b64 + `"}`),
	}
}

func TestSolanaPrepareHappyPath(t *testing.T) {
	payer := solana.NewWallet().PublicKey()
	b64 := buildSolanaTxB64(t, payer)
	svc := &Service{}

	out, err := svc.solanaPrepare(stepFor(b64, payer), lifi.QuoteParams{FromAddress: payer.String()})
	if err != nil {
		t.Fatalf("solanaPrepare: %v", err)
	}
	if out.ChainNativeAddress != payer.String() {
		t.Errorf("ChainNativeAddress = %q, want %q", out.ChainNativeAddress, payer.String())
	}
	if out.SignScheme != solanaSignScheme {
		t.Errorf("SignScheme = %d, want %d", out.SignScheme, solanaSignScheme)
	}
	if out.MessageToSignHex == "" {
		t.Error("MessageToSignHex is empty")
	}
	if out.UnsignedTxB64 != b64 {
		t.Error("UnsignedTxB64 must equal the original LI.FI snapshot")
	}
	if out.AmountOut != "5000000" {
		t.Errorf("AmountOut = %q", out.AmountOut)
	}
}

func TestSolanaPrepareRejectsWrongFeePayer(t *testing.T) {
	payer := solana.NewWallet().PublicKey()
	other := solana.NewWallet().PublicKey()
	b64 := buildSolanaTxB64(t, payer)
	svc := &Service{}

	_, err := svc.solanaPrepare(stepFor(b64, payer), lifi.QuoteParams{FromAddress: other.String()})
	if err == nil {
		t.Fatal("expected an invariant error for fee-payer mismatch")
	}
	var inv *InvariantError
	if !asInvariant(err, &inv) {
		t.Errorf("expected InvariantError, got %T: %v", err, err)
	}
}

func TestSolanaPrepareRejectsMissingTxRequest(t *testing.T) {
	payer := solana.NewWallet().PublicKey()
	svc := &Service{}
	step := stepFor("", payer)
	step.TransactionRequest = nil

	_, err := svc.solanaPrepare(step, lifi.QuoteParams{FromAddress: payer.String()})
	if err == nil {
		t.Fatal("expected an error when transactionRequest is missing")
	}
}

func asInvariant(err error, target **InvariantError) bool {
	for err != nil {
		if e, ok := err.(*InvariantError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
