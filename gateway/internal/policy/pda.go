package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// ─── helpers used by codecs/PDAs below ──────────────────────────────────────

// Canonical seed prefixes (mirror of contracts/policy-engine/src/lib.rs §2).
var (
	SeedEngine          = []byte("policy_engine")
	SeedRuleAllowlist   = []byte("rule_allowlist")
	SeedRuleVelocity    = []byte("rule_velocity")
	SeedRuleTimeLock    = []byte("rule_time_lock")
	SeedRuleOracle      = []byte("rule_oracle")
	SeedRulePasskey     = []byte("rule_passkey")
	SeedRuleFheGated    = []byte("rule_fhe_gated")
	SeedRuleSessionKey  = []byte("rule_session_key")
	SeedRuleRecovery    = []byte("rule_recovery")
	SeedSession         = []byte("session")
	SeedCPIAuthority    = []byte("__ika_cpi_authority")
)

// MemberSlotLen is the canonical 34-byte member slot length (scheme byte +
// 33-byte payload, zero-padded). Mirror of `auth::MEMBER_SLOT_LEN`.
const MemberSlotLen = 34

// MaxRules is the cap on active rules per engine (ADR PE-001).
const MaxRules = 16

// RuleKind enumerates rule kinds (mirror of contracts/policy-engine/src/lib.rs §3.3).
type RuleKind uint8

const (
	KindEmpty       RuleKind = 0
	KindAllowlist   RuleKind = 1
	KindVelocity    RuleKind = 2
	KindTimeLock    RuleKind = 3
	KindOracle      RuleKind = 4
	KindPasskey     RuleKind = 5
	KindFheGated    RuleKind = 6
	KindSessionKey  RuleKind = 7
	KindRecovery    RuleKind = 8
)

// AppliesTo bitmask (ADR PE-006).
const (
	AppliesNormal   uint8 = 1
	AppliesRecovery uint8 = 2
	AppliesSession  uint8 = 4
	AppliesAll      uint8 = AppliesNormal | AppliesRecovery | AppliesSession
)

// SeedForKind returns the PDA seed prefix for a rule kind, or an error for
// kinds without a dedicated sub-PDA (KindEmpty).
func SeedForKind(kind RuleKind) ([]byte, error) {
	switch kind {
	case KindAllowlist:
		return SeedRuleAllowlist, nil
	case KindVelocity:
		return SeedRuleVelocity, nil
	case KindTimeLock:
		return SeedRuleTimeLock, nil
	case KindOracle:
		return SeedRuleOracle, nil
	case KindPasskey:
		return SeedRulePasskey, nil
	case KindFheGated:
		return SeedRuleFheGated, nil
	case KindSessionKey:
		return SeedRuleSessionKey, nil
	case KindRecovery:
		return SeedRuleRecovery, nil
	default:
		return nil, fmt.Errorf("policy: kind %d has no PDA seed", kind)
	}
}

// InitAuthorityHashFromSlot computes sha256(init_authority_slot) — the
// 32-byte digest used in the engine PDA seed (ADR PE-008 / Audit C2 fix).
func InitAuthorityHashFromSlot(slot [MemberSlotLen]byte) [32]byte {
	return sha256.Sum256(slot[:])
}

// EnginePDA derives the PolicyEngine PDA.
// Seeds: [b"policy_engine", dwallet, init_authority_hash].
func EnginePDA(
	programID, dwallet solana.PublicKey,
	initAuthorityHash [32]byte,
) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress(
		[][]byte{SeedEngine, dwallet.Bytes(), initAuthorityHash[:]},
		programID,
	)
}

// RulePDA derives a sub-PDA for a given kind and slot inside an engine.
// Seeds: [b"rule_<kind>", engine_pda, slot_index_u8].
func RulePDA(
	programID, engine solana.PublicKey,
	kind RuleKind,
	slotIndex uint8,
) (solana.PublicKey, uint8, error) {
	seedPrefix, err := SeedForKind(kind)
	if err != nil {
		return solana.PublicKey{}, 0, err
	}
	return solana.FindProgramAddress(
		[][]byte{seedPrefix, engine.Bytes(), {slotIndex}},
		programID,
	)
}

// CPIAuthorityPDA derives the program's CPI authority PDA used as the
// dWallet's authority owner after `transfer_ownership` (ADR PE-008 Caso A).
// Seeds: [b"__ika_cpi_authority"]. Identical seed to the 8 legacy templates.
func CPIAuthorityPDA(programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{SeedCPIAuthority}, programID)
}

// SessionPDA derives an ephemeral Session PDA inside an engine (F8b).
// Seeds: [b"session", engine_pda, session_index_u32_le].
func SessionPDA(
	programID, engine solana.PublicKey,
	sessionIndex uint32,
) (solana.PublicKey, uint8, error) {
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], sessionIndex)
	return solana.FindProgramAddress(
		[][]byte{SeedSession, engine.Bytes(), idx[:]},
		programID,
	)
}

// IkaDwalletProgramID is the deployed Ika dWallet program id (matches
// `contracts/shared/src/lib.rs::IKA_DWALLET_PROGRAM_ID`).
var IkaDwalletProgramID = solana.MustPublicKeyFromBase58("87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY")

// MessageApprovalPDA derives the Ika MessageApproval PDA that
// `approve_message` writes to. Layout mirrors the legacy `policies` helper
// and `ika-pre-alpha/docs/src/reference/accounts.md`:
//
//	seeds = ["dwallet", chunks_of(curve_u16_le || dwallet_pubkey),
//	         "message_approval", scheme_u16_le, message_digest, [meta_digest]]
//
// `metaDigest` is omitted when all 32 bytes are zero (no-metadata sentinel).
func MessageApprovalPDA(
	curve uint16,
	dwalletPubkey []byte,
	scheme uint16,
	messageDigest []byte,
	metaDigest []byte,
) (solana.PublicKey, uint8, error) {
	const seedDwallet = "dwallet"
	const seedMsgApproval = "message_approval"
	if len(messageDigest) != 32 {
		return solana.PublicKey{}, 0, fmt.Errorf("message_digest must be 32 bytes")
	}
	if len(metaDigest) != 32 {
		return solana.PublicKey{}, 0, fmt.Errorf("meta_digest must be 32 bytes")
	}
	chunks := chunkDwalletSeedPayload(curve, dwalletPubkey)
	seeds := [][]byte{[]byte(seedDwallet)}
	seeds = append(seeds, chunks...)
	seeds = append(seeds, []byte(seedMsgApproval))
	schemeBytes := []byte{byte(scheme), byte(scheme >> 8)}
	seeds = append(seeds, schemeBytes)
	seeds = append(seeds, messageDigest)
	if !isAllZero(metaDigest) {
		seeds = append(seeds, metaDigest)
	}
	return solana.FindProgramAddress(seeds, IkaDwalletProgramID)
}

// chunkDwalletSeedPayload concatenates `curve_u16_le || pk` and splits it
// into ≤32-byte chunks (Solana's MAX_SEED_LEN).
func chunkDwalletSeedPayload(curve uint16, pk []byte) [][]byte {
	buf := make([]byte, 2+len(pk))
	buf[0] = byte(curve)
	buf[1] = byte(curve >> 8)
	copy(buf[2:], pk)
	chunks := make([][]byte, 0, (len(buf)+31)/32)
	for i := 0; i < len(buf); i += 32 {
		end := i + 32
		if end > len(buf) {
			end = len(buf)
		}
		chunks = append(chunks, buf[i:end])
	}
	return chunks
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
