package auth

// Audit C2 (Opção 4) — init challenges for the 7 Quasar policy templates.
//
// Each `init_policy` requires a precompile signature from the
// `init_authority` over the canonical init challenge. Mirrors byte-for-byte
// `contracts/<template>/src/challenges.rs::init_policy_challenge`.
//
// Replay protection: PDA uniqueness — `init` fails if the same
// (dwallet, init_authority_hash) pair is reused. Cross-policy replay is
// blocked by the per-template DOMAIN tag.

import "github.com/gagliardetto/solana-go"

var initOpTag = []byte("init")

// AllowlistInitPolicyChallenge — owner-only template; binds owner_slot.
func AllowlistInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
) [32]byte {
	return Hashv(
		allowlistDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
	)
}

// VelocityInitPolicyChallenge — binds owner_slot + max_sigs_per_window + window_slots.
func VelocityInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
	maxSigsPerWindow uint32,
	windowSlots uint64,
) [32]byte {
	return Hashv(
		velocityDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
		U32LE(maxSigsPerWindow),
		U64LE(windowSlots),
	)
}

// TimeLockInitPolicyChallenge — binds owner_slot + window params.
func TimeLockInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
	mode uint8,
	startSlot, endSlot, recurringPeriodSlots uint64,
) [32]byte {
	return Hashv(
		timeLockDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
		U8(mode),
		U64LE(startSlot),
		U64LE(endSlot),
		U64LE(recurringPeriodSlots),
	)
}

// OracleInitPolicyChallenge — binds owner_slot + oracle_feed + bounds + freshness + max confidence (M1).
func OracleInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
	oracleFeed solana.PublicKey,
	minPrice, maxPrice int64,
	maxAgeSlots uint64,
	maxConfidenceBps uint16,
) [32]byte {
	return Hashv(
		oracleDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
		oracleFeed.Bytes(),
		I64LE(minPrice),
		I64LE(maxPrice),
		U64LE(maxAgeSlots),
		U16LE(maxConfidenceBps),
	)
}

// PasskeyInitPolicyChallenge — binds owner_slot + threshold + passkey pubkey.
func PasskeyInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
	thresholdAmount uint64,
	passkeyPubkey [33]byte,
) [32]byte {
	return Hashv(
		passkeyDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
		U64LE(thresholdAmount),
		passkeyPubkey[:],
	)
}

// FHEGatedInitPolicyChallenge — binds owner_slot + fhe_authority + decision_max_age.
func FHEGatedInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	ownerSlot [MemberSlotLen]byte,
	fheAuthority solana.PublicKey,
	decisionMaxAgeSlots uint64,
) [32]byte {
	return Hashv(
		fheGatedDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		ownerSlot[:],
		fheAuthority.Bytes(),
		U64LE(decisionMaxAgeSlots),
	)
}

// SessionKeysInitPolicyChallenge — binds session_index + owner_slot +
// session_key + limits. Session_index is part of the PDA seed for H6
// (multiple sessions per dwallet).
func SessionKeysInitPolicyChallenge(
	dwallet solana.PublicKey,
	initAuthoritySlot [MemberSlotLen]byte,
	sessionIndex uint32,
	ownerSlot [MemberSlotLen]byte,
	sessionKey solana.PublicKey,
	expiresAtSlot, maxAmountPerTx uint64,
	maxUses uint32,
) [32]byte {
	return Hashv(
		sessionKeysDomain,
		initOpTag,
		dwallet.Bytes(),
		initAuthoritySlot[:],
		U32LE(sessionIndex),
		ownerSlot[:],
		sessionKey.Bytes(),
		U64LE(expiresAtSlot),
		U64LE(maxAmountPerTx),
		U32LE(maxUses),
	)
}
