package policy

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// TestBuildRequestSignatureIx_ClientPayer verifies the on-demand build path
// wires the client-supplied payer into the request_signature instruction as a
// writable signer (so the keeper, not the gas sponsor, pays + signs).
func TestBuildRequestSignatureIx_ClientPayer(t *testing.T) {
	s := NewService(solana.PublicKey{}) // default policy-engine program id
	h32 := strings.Repeat("00", 32)
	req := &requestSignatureSubmitRequest{
		DwalletAddress:    "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
		InitAuthorityHash: h32,
		MessageDigestHex:  h32,
		MetadataDigestHex: h32,
		UserPubkeyHex:     h32,
		DestinationHex:    h32,
		IkaDWalletPubkey:  h32, // 32-byte curve pubkey (within 1..96)
		IkaCurve:          0,
		SignatureScheme:   0,
	}
	payer := mustPub(t, "So11111111111111111111111111111111111111112")

	rec := httptest.NewRecorder()
	ix, engine, dwallet, _, ok := s.buildRequestSignatureIx(context.Background(), rec, req, payer)
	if !ok {
		t.Fatalf("buildRequestSignatureIx not ok: %s", rec.Body.String())
	}
	if engine.IsZero() || dwallet.IsZero() {
		t.Fatalf("engine/dwallet not derived")
	}
	if !ix.ProgramID().Equals(s.ProgramID) {
		t.Errorf("program id = %s, want %s", ix.ProgramID(), s.ProgramID)
	}

	js, err := serializeInstruction(ix)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// The client payer must be present as a writable signer.
	var found bool
	for _, a := range js.Accounts {
		if a.Pubkey == payer.String() {
			found = true
			if !a.IsSigner || !a.IsWritable {
				t.Errorf("payer account: signer=%v writable=%v, want both true", a.IsSigner, a.IsWritable)
			}
		}
	}
	if !found {
		t.Errorf("client payer %s not present in instruction accounts", payer)
	}
	if js.DataBase64 == "" {
		t.Errorf("empty instruction data")
	}
}
