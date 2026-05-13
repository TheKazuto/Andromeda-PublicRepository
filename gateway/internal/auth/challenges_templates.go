package auth

// Owner-style admin challenges for the 7 Quasar policy templates other
// than rules-policy. Each template has its own DOMAIN tag — copying the
// constants in `contracts/<template>/src/challenges.rs` byte-for-byte.
//
// Audit 2026-05-12 (High): admin_hash now binds the `policy` address so
// signatures cannot be replayed across policies that share the same
// (dwallet, owner). The Rust side does the same in
// `contracts/<template>/src/challenges.rs::admin_hash`.

import "github.com/gagliardetto/solana-go"

// helper — each template's domain follows the same shape as admin_hash but
// with its own DOMAIN constant. `policy` is the template-specific policy
// PDA — included to scope each signature to a specific policy account.
func ownerAdminHash(domain, opTag []byte, dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte, extras ...[]byte) [32]byte {
	parts := make([][]byte, 0, 6+len(extras))
	parts = append(parts,
		domain,
		opTag,
		dwallet.Bytes(),
		policy.Bytes(),
		U64LE(nonce),
		ownerSlot[:],
	)
	parts = append(parts, extras...)
	return Hashv(parts...)
}

// ── allowlist-destinations ─────────────────────────────────────

var (
	allowlistDomain              = []byte("andromeda::allowlist-destinations::v1")
	allowlistOpAddDestination    = []byte("add-destination")
	allowlistOpRemoveDestination = []byte("remove-destination")
	allowlistOpPause             = []byte("pause")
	allowlistOpResume            = []byte("resume")
)

func AllowlistAddDestinationChallenge(dwallet, policy solana.PublicKey, destination [32]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(allowlistDomain, allowlistOpAddDestination, dwallet, policy, nonce, ownerSlot, destination[:])
}

func AllowlistRemoveDestinationChallenge(dwallet, policy solana.PublicKey, destination [32]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(allowlistDomain, allowlistOpRemoveDestination, dwallet, policy, nonce, ownerSlot, destination[:])
}

func AllowlistPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(allowlistDomain, allowlistOpPause, dwallet, policy, nonce, ownerSlot)
}

func AllowlistResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(allowlistDomain, allowlistOpResume, dwallet, policy, nonce, ownerSlot)
}

// ── velocity-guard ─────────────────────────────────────────────

var (
	velocityDomain         = []byte("andromeda::velocity-guard::v1")
	velocityOpUpdateWindow = []byte("update-window")
	velocityOpPause        = []byte("pause")
	velocityOpResume       = []byte("resume")
)

func VelocityUpdateWindowChallenge(dwallet, policy solana.PublicKey, maxSigsPerWindow uint32, windowSlots uint64, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(velocityDomain, velocityOpUpdateWindow, dwallet, policy, nonce, ownerSlot, U32LE(maxSigsPerWindow), U64LE(windowSlots))
}

func VelocityPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(velocityDomain, velocityOpPause, dwallet, policy, nonce, ownerSlot)
}

func VelocityResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(velocityDomain, velocityOpResume, dwallet, policy, nonce, ownerSlot)
}

// ── time-lock ──────────────────────────────────────────────────

var (
	timeLockDomain         = []byte("andromeda::time-lock::v1")
	timeLockOpUpdateWindow = []byte("update-window")
	timeLockOpPause        = []byte("pause")
	timeLockOpResume       = []byte("resume")
)

func TimeLockUpdateWindowChallenge(dwallet, policy solana.PublicKey, mode uint8, startSlot, endSlot, recurringPeriodSlots uint64, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(timeLockDomain, timeLockOpUpdateWindow, dwallet, policy, nonce, ownerSlot,
		U8(mode), U64LE(startSlot), U64LE(endSlot), U64LE(recurringPeriodSlots))
}

func TimeLockPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(timeLockDomain, timeLockOpPause, dwallet, policy, nonce, ownerSlot)
}

func TimeLockResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(timeLockDomain, timeLockOpResume, dwallet, policy, nonce, ownerSlot)
}

// ── oracle-conditional ─────────────────────────────────────────

var (
	oracleDomain         = []byte("andromeda::oracle-conditional::v1")
	oracleOpUpdateBounds = []byte("update-bounds")
	oracleOpPause        = []byte("pause")
	oracleOpResume       = []byte("resume")
)

func OracleUpdateBoundsChallenge(dwallet, policy solana.PublicKey, minPrice, maxPrice int64, maxAgeSlots uint64, maxConfidenceBps uint16, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(oracleDomain, oracleOpUpdateBounds, dwallet, policy, nonce, ownerSlot,
		I64LE(minPrice), I64LE(maxPrice), U64LE(maxAgeSlots), U16LE(maxConfidenceBps))
}

func OraclePauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(oracleDomain, oracleOpPause, dwallet, policy, nonce, ownerSlot)
}

func OracleResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(oracleDomain, oracleOpResume, dwallet, policy, nonce, ownerSlot)
}

// ── passkey-step-up ────────────────────────────────────────────

var (
	passkeyDomain         = []byte("andromeda::passkey-step-up::v1")
	passkeyOpUpdatePolicy = []byte("update-policy")
	passkeyOpPause        = []byte("pause")
	passkeyOpResume       = []byte("resume")
	passkeyOpStepUp       = []byte("step-up")
)

func PasskeyUpdatePolicyChallenge(dwallet, policy solana.PublicKey, thresholdAmount uint64, passkeyPubkey [33]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(passkeyDomain, passkeyOpUpdatePolicy, dwallet, policy, nonce, ownerSlot,
		U64LE(thresholdAmount), passkeyPubkey[:])
}

func PasskeyPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(passkeyDomain, passkeyOpPause, dwallet, policy, nonce, ownerSlot)
}

func PasskeyResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(passkeyDomain, passkeyOpResume, dwallet, policy, nonce, ownerSlot)
}

// PasskeyStepUpChallenge — what the WebAuthn passkey assertion's
// `clientDataJSON.challenge` MUST equal (base64url-no-pad). This is NOT an
// admin op (it authorizes a single signature), so it does not flow through
// `ownerAdminHash` and does not include the `policy` address. The on-chain
// equivalent lives in `contracts/passkey-step-up/src/challenges.rs::
// step_up_challenge` and is signed by the passkey, not the owner.
func PasskeyStepUpChallenge(dwallet solana.PublicKey, messageDigest [32]byte, txAmount uint64, nonce uint64, passkeyPubkey [33]byte) [32]byte {
	return Hashv(
		passkeyDomain,
		passkeyOpStepUp,
		dwallet.Bytes(),
		messageDigest[:],
		U64LE(txAmount),
		U64LE(nonce),
		passkeyPubkey[:],
	)
}

// ── session-keys ───────────────────────────────────────────────

var (
	sessionKeysDomain                 = []byte("andromeda::session-keys::v1")
	sessionKeysOpCreateSession        = []byte("create-session")
	sessionKeysOpRevokeSession        = []byte("revoke-session")
	sessionKeysOpAddAllowedProgram    = []byte("add-allowed-program")
	sessionKeysOpRemoveAllowedProgram = []byte("remove-allowed-program")
	sessionKeysOpCloseSession         = []byte("close-session")
)

// SessionKeysCreateSessionChallenge — signed with nonce=0 to authorize the
// initial create_session ix.
func SessionKeysCreateSessionChallenge(dwallet, policy solana.PublicKey, sessionKey solana.PublicKey, expiresAtSlot, maxAmountPerTx uint64, maxUses uint32, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(sessionKeysDomain, sessionKeysOpCreateSession, dwallet, policy, 0, ownerSlot,
		sessionKey.Bytes(), U64LE(expiresAtSlot), U64LE(maxAmountPerTx), U32LE(maxUses))
}

func SessionKeysRevokeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(sessionKeysDomain, sessionKeysOpRevokeSession, dwallet, policy, nonce, ownerSlot)
}

func SessionKeysAddAllowedProgramChallenge(dwallet, policy, programID solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(sessionKeysDomain, sessionKeysOpAddAllowedProgram, dwallet, policy, nonce, ownerSlot, programID.Bytes())
}

func SessionKeysRemoveAllowedProgramChallenge(dwallet, policy, programID solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(sessionKeysDomain, sessionKeysOpRemoveAllowedProgram, dwallet, policy, nonce, ownerSlot, programID.Bytes())
}

func SessionKeysCloseSessionChallenge(dwallet, policy, recipient solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(sessionKeysDomain, sessionKeysOpCloseSession, dwallet, policy, nonce, ownerSlot, recipient.Bytes())
}

// ── fhe-gated ──────────────────────────────────────────────────

var (
	fheGatedDomain         = []byte("andromeda::fhe-gated::v1")
	fheGatedDomainDecision = []byte("andromeda::fhe-gated::decision::v1")
	fheGatedOpRotate       = []byte("rotate-authority")
	fheGatedOpPause        = []byte("pause")
	fheGatedOpResume       = []byte("resume")
)

func FHEGatedRotateAuthorityChallenge(dwallet, policy, newFheAuthority solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(fheGatedDomain, fheGatedOpRotate, dwallet, policy, nonce, ownerSlot, newFheAuthority.Bytes())
}

func FHEGatedPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(fheGatedDomain, fheGatedOpPause, dwallet, policy, nonce, ownerSlot)
}

func FHEGatedResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) [32]byte {
	return ownerAdminHash(fheGatedDomain, fheGatedOpResume, dwallet, policy, nonce, ownerSlot)
}

// FHEGatedDecisionCanonicalBytes — the digest the Vault Transit
// `andromeda-fhe` Ed25519 key must sign for `request_signature` to
// succeed on-chain. Mirrors `contracts/fhe-gated/src/challenges.rs::
// decision_canonical_bytes`.
func FHEGatedDecisionCanonicalBytes(policy solana.PublicKey, messageDigest [32]byte, decisionCreatedSlot uint64, decisionAuthorize uint8) [32]byte {
	return Hashv(
		fheGatedDomainDecision,
		policy.Bytes(),
		messageDigest[:],
		U64LE(decisionCreatedSlot),
		U8(decisionAuthorize),
	)
}
