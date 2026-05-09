package auth

// Challenges for the rules-policy v2 program (Andromeda Recovery Layer).
// Mirrors `contracts/auth/src/challenge.rs` byte-for-byte.

import "github.com/gagliardetto/solana-go"

var (
	rulesPolicyDomain                  = []byte("andromeda::rules-policy::v1")
	opPrimaryRecover                   = []byte("primary-recover")
	opQuorumSessionOpen                = []byte("quorum-session-open")
	opQuorumContribute                 = []byte("quorum-contribute")
	opAdminAddMember                   = []byte("admin-add-member")
	opAdminRemoveMember                = []byte("admin-remove-member")
	opAdminAddDestination              = []byte("admin-add-destination")
	opAdminRemoveDestination           = []byte("admin-remove-destination")
	opAdminRevoke                      = []byte("admin-revoke")
	opAdminSetPrimary                  = []byte("admin-set-primary")
	opAdminSetQuorumThresholdImmediate = []byte("admin-set-qt-immediate")
	opAdminSetDailyLimitImmediate      = []byte("admin-set-dl-immediate")
	opAdminSetCooldownImmediate        = []byte("admin-set-cd-immediate")
	opAdminProposeQuorumThreshold      = []byte("admin-propose-qt")
	opAdminProposeDailyLimit           = []byte("admin-propose-dl")
	opAdminProposeCooldown             = []byte("admin-propose-cd")
)

// PrimaryRecoverChallenge — bytes the primary signs for `recover_as_primary`.
func PrimaryRecoverChallenge(
	dwallet solana.PublicKey,
	messageDigest [32]byte,
	metadataDigest [32]byte,
	nonce uint64,
	primarySlot [MemberSlotLen]byte,
) [32]byte {
	return Hashv(
		rulesPolicyDomain,
		opPrimaryRecover,
		dwallet.Bytes(),
		messageDigest[:],
		metadataDigest[:],
		U64LE(nonce),
		primarySlot[:],
	)
}

// QuorumSessionOpenChallenge — bytes the primary signs to authorize opening
// a new quorum recovery session.
func QuorumSessionOpenChallenge(
	dwallet solana.PublicKey,
	messageDigest [32]byte,
	metadataDigest [32]byte,
	amount uint64,
	destination [32]byte,
	expiresAt int64,
	sessionNonce uint64,
	primarySlot [MemberSlotLen]byte,
) [32]byte {
	return Hashv(
		rulesPolicyDomain,
		opQuorumSessionOpen,
		dwallet.Bytes(),
		messageDigest[:],
		metadataDigest[:],
		U64LE(amount),
		destination[:],
		I64LE(expiresAt),
		U64LE(sessionNonce),
		primarySlot[:],
	)
}

// QuorumContributeChallenge — bytes a single quorum member signs to add
// their contribution to a session.
func QuorumContributeChallenge(
	session solana.PublicKey,
	memberSlot [MemberSlotLen]byte,
) [32]byte {
	return Hashv(
		rulesPolicyDomain,
		opQuorumContribute,
		session.Bytes(),
		memberSlot[:],
	)
}

// adminHash assembles the canonical admin-action challenge for the rules-policy.
func adminHash(opTag []byte, dwallet solana.PublicKey, nonce uint64, primarySlot [MemberSlotLen]byte, extras ...[]byte) [32]byte {
	parts := make([][]byte, 0, 5+len(extras))
	parts = append(parts,
		rulesPolicyDomain,
		opTag,
		dwallet.Bytes(),
		U64LE(nonce),
		primarySlot[:],
	)
	parts = append(parts, extras...)
	return Hashv(parts...)
}

// AdminAddMemberChallenge.
func AdminAddMemberChallenge(dwallet solana.PublicKey, newMemberSlot [MemberSlotLen]byte, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminAddMember, dwallet, nonce, primarySlot, newMemberSlot[:])
}

// AdminRemoveMemberChallenge.
func AdminRemoveMemberChallenge(dwallet solana.PublicKey, memberSlot [MemberSlotLen]byte, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminRemoveMember, dwallet, nonce, primarySlot, memberSlot[:])
}

// AdminAddDestinationChallenge.
func AdminAddDestinationChallenge(dwallet solana.PublicKey, destination [32]byte, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminAddDestination, dwallet, nonce, primarySlot, destination[:])
}

// AdminRemoveDestinationChallenge.
func AdminRemoveDestinationChallenge(dwallet solana.PublicKey, destination [32]byte, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminRemoveDestination, dwallet, nonce, primarySlot, destination[:])
}

// AdminRevokeChallenge.
func AdminRevokeChallenge(dwallet solana.PublicKey, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminRevoke, dwallet, nonce, primarySlot)
}

// AdminSetPrimaryChallenge — `currentPrimarySlot` is signed by the *current*
// primary; the new slot replaces it after the on-chain ix succeeds.
func AdminSetPrimaryChallenge(dwallet solana.PublicKey, newPrimarySlot [MemberSlotLen]byte, nonce uint64, currentPrimarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminSetPrimary, dwallet, nonce, currentPrimarySlot, newPrimarySlot[:])
}

// AdminSetQuorumThresholdImmediateChallenge.
func AdminSetQuorumThresholdImmediateChallenge(dwallet solana.PublicKey, newThreshold uint8, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminSetQuorumThresholdImmediate, dwallet, nonce, primarySlot, U8(newThreshold))
}

// AdminSetDailyLimitImmediateChallenge.
func AdminSetDailyLimitImmediateChallenge(dwallet solana.PublicKey, newSome bool, newLimit uint64, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	someByte := uint8(0)
	if newSome {
		someByte = 1
	}
	return adminHash(opAdminSetDailyLimitImmediate, dwallet, nonce, primarySlot, U8(someByte), U64LE(newLimit))
}

// AdminSetCooldownImmediateChallenge.
func AdminSetCooldownImmediateChallenge(dwallet solana.PublicKey, newCooldownSeconds uint64, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminSetCooldownImmediate, dwallet, nonce, primarySlot, U64LE(newCooldownSeconds))
}

// AdminProposeQuorumThresholdChallenge.
func AdminProposeQuorumThresholdChallenge(dwallet solana.PublicKey, newThreshold uint8, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminProposeQuorumThreshold, dwallet, nonce, primarySlot, U8(newThreshold))
}

// AdminProposeDailyLimitChallenge.
func AdminProposeDailyLimitChallenge(dwallet solana.PublicKey, newSome bool, newLimit uint64, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	someByte := uint8(0)
	if newSome {
		someByte = 1
	}
	return adminHash(opAdminProposeDailyLimit, dwallet, nonce, primarySlot, U8(someByte), U64LE(newLimit))
}

// AdminProposeCooldownChallenge.
func AdminProposeCooldownChallenge(dwallet solana.PublicKey, newCooldownSeconds uint64, nonce uint64, primarySlot [MemberSlotLen]byte) [32]byte {
	return adminHash(opAdminProposeCooldown, dwallet, nonce, primarySlot, U64LE(newCooldownSeconds))
}
