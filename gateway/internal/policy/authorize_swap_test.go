package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// TestAuthorizeSwap_RequiresOwnerAuth proves the zero-trust guard at the policy
// boundary: AuthorizeSwap fails fast (no tx assembly, no broadcast) when the
// dWallet owner's slot + signature are absent. The Fase 1 (A1) on-chain check
// would reject the tx anyway, but failing here surfaces a clear 4xx instead of
// burning gas on a doomed land. The guard runs BEFORE the gas-sponsor check
// (cheapest rejection first), so the test does not need a sponsor.
func TestAuthorizeSwap_RequiresOwnerAuth(t *testing.T) {
	svc := &Service{ProgramID: solana.SystemProgramID}
	_, err := svc.AuthorizeSwap(context.Background(), SwapAuthorizeInput{
		// missing OwnerSlotHex + OwnerSignatureBase64
		DwalletAddress:       solana.SystemProgramID.String(),
		InitAuthorityHashHex: zero32Hex(),
		MessageDigestHex:     zero32Hex(),
		UserPubkeyHex:        zero32Hex(),
		IkaDWalletPubkeyHex:  zero32Hex(),
	})
	if err == nil {
		t.Fatal("AuthorizeSwap without owner_slot/signature: want error, got nil")
	}
	if !strings.Contains(err.Error(), "owner_auth_required") {
		t.Errorf("want owner_auth_required error, got %v", err)
	}
}

// TestSwapOwnerAuthChallenge_StableForFixedInputs proves the challenge is a
// pure function of the inputs (the gateway can't lie about what the owner is
// signing — the same inputs always produce the same digest).
func TestSwapOwnerAuthChallenge_StableForFixedInputs(t *testing.T) {
	svc := &Service{ProgramID: solana.SystemProgramID}
	in := SwapAuthorizeInput{
		DwalletAddress:       solana.SystemProgramID.String(),
		InitAuthorityHashHex: zero32Hex(),
		MessageDigestHex:     "01" + zero32Hex()[2:],
		UserPubkeyHex:        zero32Hex(),
		OwnerSlotHex:         zeroSlotHex(),
	}
	a, err := svc.SwapOwnerAuthChallenge(in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := svc.SwapOwnerAuthChallenge(in)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a.OwnerAuthChallengeHex == "" || a.OwnerAuthChallengeHex != b.OwnerAuthChallengeHex {
		t.Fatalf("challenge drift: %q vs %q", a.OwnerAuthChallengeHex, b.OwnerAuthChallengeHex)
	}
	if !strings.HasPrefix(a.HumanMessage, "Sign for dWallet ") {
		t.Errorf("human message: %q", a.HumanMessage)
	}
}

// TestSwapOwnerAuthChallenge_ChangesWithMessageDigest proves the challenge
// binds the message_digest — a gateway swap of the underlying transaction
// invalidates the owner's signature on-chain.
func TestSwapOwnerAuthChallenge_ChangesWithMessageDigest(t *testing.T) {
	svc := &Service{ProgramID: solana.SystemProgramID}
	base := SwapAuthorizeInput{
		DwalletAddress:       solana.SystemProgramID.String(),
		InitAuthorityHashHex: zero32Hex(),
		UserPubkeyHex:        zero32Hex(),
		OwnerSlotHex:         zeroSlotHex(),
	}
	base.MessageDigestHex = "01" + zero32Hex()[2:]
	first, err := svc.SwapOwnerAuthChallenge(base)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	base.MessageDigestHex = "02" + zero32Hex()[2:]
	second, err := svc.SwapOwnerAuthChallenge(base)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.OwnerAuthChallengeHex == second.OwnerAuthChallengeHex {
		t.Fatal("challenge did not change when message_digest changed (zero-trust binding broken)")
	}
}

// helpers — local zeros to avoid importing strings/hex everywhere.

func zero32Hex() string   { return strings.Repeat("00", 32) }
func zeroSlotHex() string { return strings.Repeat("00", MemberSlotLen) }
