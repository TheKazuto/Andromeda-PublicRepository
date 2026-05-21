package auth

// Owner-style admin challenges for the 7 Quasar policy templates other
// than rules-policy. Each template has its own DOMAIN tag — copying the
// constants in `contracts/<template>/src/challenges.rs` byte-for-byte.
//
// Clear-signing v2 (2026-05-14): DOMAIN bumped to v2 for governance ops,
// with init / request-signature / step-up / decision preserved at v1 in
// separate constants. The hash now embeds `human_len_u16_le ||
// human_message_bytes` right after the op tag, and every `*Challenge`
// returns `(hash, humanMessage, ClearSigning, error)`.
//
// Audit 2026-05-12 (High): admin_hash binds the `policy` address so
// signatures cannot be replayed across policies that share the same
// (dwallet, owner). The Rust side does the same in
// `contracts/<template>/src/challenges.rs::admin_hash_with_human`.

import (
	"encoding/hex"
	"strconv"

	"github.com/gagliardetto/solana-go"
)

// ownerAdminHashWithHuman matches `admin_hash_with_human` in each policy
// crate. `human` MUST be the bytes returned by the corresponding renderer
// in `clear_signing.go` — never caller-supplied.
func ownerAdminHashWithHuman(domain, opTag []byte, human []byte, dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte, extras ...[]byte) [32]byte {
	parts := make([][]byte, 0, 8+len(extras))
	parts = append(parts,
		domain,
		opTag,
		HumanLenLE(human),
		human,
		dwallet.Bytes(),
		policy.Bytes(),
		U64LE(nonce),
		ownerSlot[:],
	)
	parts = append(parts, extras...)
	return Hashv(parts...)
}

func baseAdminFields(dwallet, policy solana.PublicKey, expectedNonce uint64) map[string]any {
	return map[string]any{
		"dwallet":        dwallet.String(),
		"policy":         policy.String(),
		"expected_nonce": strconv.FormatUint(expectedNonce, 10),
	}
}

// ── allowlist-destinations ─────────────────────────────────────

var (
	allowlistDomain              = []byte("andromeda::allowlist-destinations::v2")
	allowlistOpAddDestination    = []byte("add-destination")
	allowlistOpRemoveDestination = []byte("remove-destination")
	allowlistOpPause             = []byte("pause")
	allowlistOpResume            = []byte("resume")
)

func AllowlistAddDestinationChallenge(dwallet, policy solana.PublicKey, destination [32]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := AllowlistAddDestinationMessage(destination, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(allowlistDomain, allowlistOpAddDestination, []byte(human), dwallet, policy, nonce, ownerSlot, destination[:])
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "allowlist.add_destination",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["destination_hex"] = hex.EncodeToString(destination[:])
	return hash, human, cs, nil
}

func AllowlistRemoveDestinationChallenge(dwallet, policy solana.PublicKey, destination [32]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := AllowlistRemoveDestinationMessage(destination, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(allowlistDomain, allowlistOpRemoveDestination, []byte(human), dwallet, policy, nonce, ownerSlot, destination[:])
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "allowlist.remove_destination",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["destination_hex"] = hex.EncodeToString(destination[:])
	return hash, human, cs, nil
}

func AllowlistPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := AllowlistPauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(allowlistDomain, allowlistOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "allowlist.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func AllowlistResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := AllowlistResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(allowlistDomain, allowlistOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "allowlist.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// ── velocity-guard ─────────────────────────────────────────────

var (
	velocityDomain         = []byte("andromeda::velocity-guard::v2")
	velocityOpUpdateWindow = []byte("update-window")
	velocityOpPause        = []byte("pause")
	velocityOpResume       = []byte("resume")
)

func VelocityUpdateWindowChallenge(dwallet, policy solana.PublicKey, maxSigsPerWindow uint32, windowSlots uint64, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := VelocityUpdateWindowMessage(maxSigsPerWindow, windowSlots, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(velocityDomain, velocityOpUpdateWindow, []byte(human), dwallet, policy, nonce, ownerSlot, U32LE(maxSigsPerWindow), U64LE(windowSlots))
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "velocity.update_window",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["max_sigs_per_window"] = maxSigsPerWindow
	cs.Fields["window_slots"] = strconv.FormatUint(windowSlots, 10)
	return hash, human, cs, nil
}

func VelocityPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := VelocityPauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(velocityDomain, velocityOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "velocity.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func VelocityResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := VelocityResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(velocityDomain, velocityOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "velocity.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// ── time-lock ──────────────────────────────────────────────────

var (
	timeLockDomain         = []byte("andromeda::time-lock::v2")
	timeLockOpUpdateWindow = []byte("update-window")
	timeLockOpPause        = []byte("pause")
	timeLockOpResume       = []byte("resume")
)

func TimeLockUpdateWindowChallenge(dwallet, policy solana.PublicKey, mode uint8, startSlot, endSlot, recurringPeriodSlots uint64, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := TimeLockUpdateWindowMessage(mode, startSlot, endSlot, recurringPeriodSlots, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(timeLockDomain, timeLockOpUpdateWindow, []byte(human), dwallet, policy, nonce, ownerSlot,
		U8(mode), U64LE(startSlot), U64LE(endSlot), U64LE(recurringPeriodSlots))
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "time_lock.update_window",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["mode"] = mode
	cs.Fields["start_slot"] = strconv.FormatUint(startSlot, 10)
	cs.Fields["end_slot"] = strconv.FormatUint(endSlot, 10)
	cs.Fields["recurring_period_slots"] = strconv.FormatUint(recurringPeriodSlots, 10)
	return hash, human, cs, nil
}

func TimeLockPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := TimeLockPauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(timeLockDomain, timeLockOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "time_lock.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func TimeLockResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := TimeLockResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(timeLockDomain, timeLockOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "time_lock.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// ── oracle-conditional ─────────────────────────────────────────

var (
	oracleDomain         = []byte("andromeda::oracle-conditional::v2")
	oracleOpUpdateBounds = []byte("update-bounds")
	oracleOpPause        = []byte("pause")
	oracleOpResume       = []byte("resume")
)

func OracleUpdateBoundsChallenge(dwallet, policy solana.PublicKey, minPrice, maxPrice int64, maxAgeSlots uint64, maxConfidenceBps uint16, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := OracleUpdateBoundsMessage(minPrice, maxPrice, maxAgeSlots, maxConfidenceBps, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(oracleDomain, oracleOpUpdateBounds, []byte(human), dwallet, policy, nonce, ownerSlot,
		I64LE(minPrice), I64LE(maxPrice), U64LE(maxAgeSlots), U16LE(maxConfidenceBps))
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "oracle.update_bounds",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["min_price"] = strconv.FormatInt(minPrice, 10)
	cs.Fields["max_price"] = strconv.FormatInt(maxPrice, 10)
	cs.Fields["max_age_slots"] = strconv.FormatUint(maxAgeSlots, 10)
	cs.Fields["max_confidence_bps"] = maxConfidenceBps
	return hash, human, cs, nil
}

func OraclePauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := OraclePauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(oracleDomain, oracleOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "oracle.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func OracleResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := OracleResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(oracleDomain, oracleOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "oracle.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// ── passkey-step-up ────────────────────────────────────────────

var (
	passkeyDomain         = []byte("andromeda::passkey-step-up::v2")
	passkeyDomainStepUpV1 = []byte("andromeda::passkey-step-up::v1")
	passkeyOpUpdatePolicy = []byte("update-policy")
	passkeyOpPause        = []byte("pause")
	passkeyOpResume       = []byte("resume")
	passkeyOpStepUp       = []byte("step-up")
)

func PasskeyUpdatePolicyChallenge(dwallet, policy solana.PublicKey, thresholdAmount uint64, passkeyPubkey [33]byte, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := PasskeyUpdatePolicyMessage(thresholdAmount, passkeyPubkey, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(passkeyDomain, passkeyOpUpdatePolicy, []byte(human), dwallet, policy, nonce, ownerSlot,
		U64LE(thresholdAmount), passkeyPubkey[:])
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "passkey.update_policy",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["threshold_amount"] = strconv.FormatUint(thresholdAmount, 10)
	cs.Fields["passkey_pubkey_hex"] = hex.EncodeToString(passkeyPubkey[:])
	return hash, human, cs, nil
}

func PasskeyPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := PasskeyPauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(passkeyDomain, passkeyOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "passkey.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func PasskeyResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := PasskeyResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(passkeyDomain, passkeyOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "passkey.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// PasskeyStepUpChallenge — what the WebAuthn passkey assertion's
// `clientDataJSON.challenge` MUST equal (base64url-no-pad). Preserved at
// v1 (no clear signing — WebAuthn assertion has its own clientDataJSON
// embedding). Mirrors `contracts/passkey-step-up/src/challenges.rs::
// step_up_challenge` byte-for-byte.
func PasskeyStepUpChallenge(dwallet solana.PublicKey, messageDigest [32]byte, txAmount uint64, nonce uint64, passkeyPubkey [33]byte) [32]byte {
	return Hashv(
		passkeyDomainStepUpV1,
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
	sessionKeysDomain                 = []byte("andromeda::session-keys::v2")
	sessionKeysDomainInitV1           = []byte("andromeda::session-keys::v1")
	sessionKeysOpCreateSession        = []byte("create-session")
	sessionKeysOpRevokeSession        = []byte("revoke-session")
	sessionKeysOpAddAllowedProgram    = []byte("add-allowed-program")
	sessionKeysOpRemoveAllowedProgram = []byte("remove-allowed-program")
	sessionKeysOpCloseSession         = []byte("close-session")
)

// SessionKeysCreateSessionChallenge — init flow, preserved at v1 (no
// clear signing). Mirrors the v1 `create_session_challenge` in
// `contracts/session-keys/src/challenges.rs`.
func SessionKeysCreateSessionChallenge(dwallet, policy solana.PublicKey, sessionKey solana.PublicKey, expiresAtSlot, maxAmountPerTx uint64, maxUses uint32, ownerSlot [MemberSlotLen]byte) [32]byte {
	return Hashv(
		sessionKeysDomainInitV1,
		sessionKeysOpCreateSession,
		dwallet.Bytes(),
		policy.Bytes(),
		U64LE(0),
		ownerSlot[:],
		sessionKey.Bytes(),
		U64LE(expiresAtSlot),
		U64LE(maxAmountPerTx),
		U32LE(maxUses),
	)
}

func SessionKeysRevokeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := SessionKeysRevokeSessionMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(sessionKeysDomain, sessionKeysOpRevokeSession, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "session_keys.revoke",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func SessionKeysAddAllowedProgramChallenge(dwallet, policy, programID solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := SessionKeysAddAllowedProgramMessage(programID, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(sessionKeysDomain, sessionKeysOpAddAllowedProgram, []byte(human), dwallet, policy, nonce, ownerSlot, programID.Bytes())
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "session_keys.add_allowed_program",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["program_id"] = programID.String()
	return hash, human, cs, nil
}

func SessionKeysRemoveAllowedProgramChallenge(dwallet, policy, programID solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := SessionKeysRemoveAllowedProgramMessage(programID, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(sessionKeysDomain, sessionKeysOpRemoveAllowedProgram, []byte(human), dwallet, policy, nonce, ownerSlot, programID.Bytes())
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "session_keys.remove_allowed_program",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["program_id"] = programID.String()
	return hash, human, cs, nil
}

func SessionKeysCloseSessionChallenge(dwallet, policy, recipient solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := SessionKeysCloseSessionMessage(recipient, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(sessionKeysDomain, sessionKeysOpCloseSession, []byte(human), dwallet, policy, nonce, ownerSlot, recipient.Bytes())
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "session_keys.close_session",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["recipient"] = recipient.String()
	return hash, human, cs, nil
}

// ── fhe-gated ──────────────────────────────────────────────────

var (
	fheGatedDomain         = []byte("andromeda::fhe-gated::v2")
	fheGatedDomainDecision = []byte("andromeda::fhe-gated::decision::v1")
	fheGatedOpRotate       = []byte("rotate-authority")
	fheGatedOpPause        = []byte("pause")
	fheGatedOpResume       = []byte("resume")
)

func FHEGatedRotateAuthorityChallenge(dwallet, policy, newFheAuthority solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := FHERotateAuthorityMessage(newFheAuthority, policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(fheGatedDomain, fheGatedOpRotate, []byte(human), dwallet, policy, nonce, ownerSlot, newFheAuthority.Bytes())
	cs := ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "fhe.rotate_authority",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}
	cs.Fields["new_fhe_authority"] = newFheAuthority.String()
	return hash, human, cs, nil
}

func FHEGatedPauseChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := FHEPauseMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(fheGatedDomain, fheGatedOpPause, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "fhe.pause",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

func FHEGatedResumeChallenge(dwallet, policy solana.PublicKey, nonce uint64, ownerSlot [MemberSlotLen]byte) ([32]byte, string, ClearSigning, error) {
	human, err := FHEResumeMessage(policy, dwallet)
	if err != nil {
		return [32]byte{}, "", ClearSigning{}, err
	}
	hash := ownerAdminHashWithHuman(fheGatedDomain, fheGatedOpResume, []byte(human), dwallet, policy, nonce, ownerSlot)
	return hash, human, ClearSigning{
		Version:   ClearSigningVersionPolicy,
		Operation: "fhe.resume",
		Fields:    baseAdminFields(dwallet, policy, nonce),
	}, nil
}

// FHEGatedDecisionCanonicalBytes — the digest the Vault Transit
// `andromeda-fhe` Ed25519 key must sign for `request_signature` to
// succeed on-chain. Preserved at v1 (KMS signer, not a human, no clear
// signing). Mirrors `contracts/fhe-gated/src/challenges.rs::
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
