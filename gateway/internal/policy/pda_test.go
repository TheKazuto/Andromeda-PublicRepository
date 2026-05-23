package policy

import "testing"

// TestMessageApprovalPDA_MetadataSeedConditional locks the Update 6 F0 rule:
// the Ika message_metadata_digest is the FINAL MessageApproval seed, present
// ONLY when non-zero. Zero/nil reproduces the pre-Update-6 derivation for every
// chain without signing metadata.
func TestMessageApprovalPDA_MetadataSeedConditional(t *testing.T) {
	const curve = uint16(0) // Secp256k1
	pk := make([]byte, 33)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	const scheme = uint16(4) // EcdsaBlake2b256 (Zcash)
	msgDigest := make([]byte, 32)
	for i := range msgDigest {
		msgDigest[i] = 0xAB
	}

	// nil and all-zero metadata MUST derive the SAME address (no extra seed).
	pdaNil, _, err := MessageApprovalPDA(curve, pk, scheme, msgDigest, nil)
	if err != nil {
		t.Fatalf("nil metadata: %v", err)
	}
	pdaZero, _, err := MessageApprovalPDA(curve, pk, scheme, msgDigest, make([]byte, 32))
	if err != nil {
		t.Fatalf("zero metadata: %v", err)
	}
	if pdaNil != pdaZero {
		t.Errorf("nil and all-zero metadata must derive the same PDA: %s != %s", pdaNil, pdaZero)
	}

	// A non-zero metadata digest MUST change the address (extra seed included).
	meta := make([]byte, 32)
	for i := range meta {
		meta[i] = 0xCD
	}
	pdaMeta, _, err := MessageApprovalPDA(curve, pk, scheme, msgDigest, meta)
	if err != nil {
		t.Fatalf("non-zero metadata: %v", err)
	}
	if pdaMeta == pdaNil {
		t.Error("a non-zero metadata digest must derive a DIFFERENT PDA (the extra metadata seed)")
	}
}

func TestMessageApprovalPDA_RejectsBadDigest(t *testing.T) {
	if _, _, err := MessageApprovalPDA(0, make([]byte, 33), 0, make([]byte, 31), nil); err == nil {
		t.Error("expected error for a non-32-byte message digest")
	}
}
