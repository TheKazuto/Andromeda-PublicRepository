package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Discriminators for F4-F7.
const (
	DiscAddRuleTimeLock                 uint8 = 12
	DiscAddRuleOracle                   uint8 = 13
	DiscAddRulePasskey                  uint8 = 14
	DiscAddRuleFheGated                 uint8 = 15
	// C2 audit fix (2026-05-16): populates `KIND_FHE_GATED.authorities_flat`
	// after add_rule_fhe_gated (which initialises count=0). Without this,
	// any KIND_FHE_GATED dispatch fails fast with InvalidRuleHeader.
	DiscUpdateRuleFheGatedAuthorities   uint8 = 126
)

// MaxFheAuthorities mirrors `MAX_FHE_AUTHORITIES` in lib.rs.
const MaxFheAuthorities = 4

// ── F4 — TimeLock ──────────────────────────────────────────────────────────

const (
	TimeLockModeAbsolute uint8 = 0
	TimeLockModeDelay    uint8 = 1
)

type AddRuleTimeLockParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	AppliesTo         uint8
	Mode              uint8 // 0 absolute / 1 delay
	UnlockTs          int64
	DelaySeconds      uint64
}

func AddRuleTimeLock(p AddRuleTimeLockParams) (solana.Instruction, error) {
	if p.Mode != TimeLockModeAbsolute && p.Mode != TimeLockModeDelay {
		return nil, fmt.Errorf("policy: time-lock mode must be 0 or 1 (got %d)", p.Mode)
	}
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindTimeLock, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, 1+32+8+1+1+1+8+8)
	data = append(data, DiscAddRuleTimeLock)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo, p.Mode)
	binary.LittleEndian.PutUint64(b[:], uint64(p.UnlockTs))
	data = append(data, b[:]...)
	binary.LittleEndian.PutUint64(b[:], p.DelaySeconds)
	data = append(data, b[:]...)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// TimeLockConfigHash. Note: `created_at_ts` is runtime state (set on-chain
// when the rule is added) and intentionally NOT part of the hash.
func TimeLockConfigHash(appliesTo, mode uint8, unlockTs int64, delaySeconds uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("time-lock-config-v1"))
	h.Write([]byte{appliesTo, mode})
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(unlockTs))
	h.Write(b[:])
	binary.LittleEndian.PutUint64(b[:], delaySeconds)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ── F5 — Oracle ────────────────────────────────────────────────────────────

type AddRuleOracleParams struct {
	ProgramID            solana.PublicKey
	Engine               solana.PublicKey
	DWallet              solana.PublicKey
	Payer                solana.PublicKey
	InitAuthorityHash    [32]byte
	ExpectedNonce        uint64
	RuleIndex            uint8
	AppliesTo            uint8
	FreshnessSecondsDiv16 uint8
	MinConfidenceBpsDiv4  uint8
}

func AddRuleOracle(p AddRuleOracleParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindOracle, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+1+1+1)
	data = append(data, DiscAddRuleOracle)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo, p.FreshnessSecondsDiv16, p.MinConfidenceBpsDiv4)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// ── F6 — Passkey step-up ───────────────────────────────────────────────────

type AddRulePasskeyParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	AppliesTo         uint8
}

func AddRulePasskey(p AddRulePasskeyParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindPasskey, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+1)
	data = append(data, DiscAddRulePasskey)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// ── F7 — FheGated ──────────────────────────────────────────────────────────

type AddRuleFheGatedParams struct {
	ProgramID             solana.PublicKey
	Engine                solana.PublicKey
	DWallet               solana.PublicKey
	Payer                 solana.PublicKey
	InitAuthorityHash     [32]byte
	ExpectedNonce         uint64
	RuleIndex             uint8
	AppliesTo             uint8
	FreshnessSecondsDiv16 uint8
}

func AddRuleFheGated(p AddRuleFheGatedParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindFheGated, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+1+1)
	data = append(data, DiscAddRuleFheGated)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo, p.FreshnessSecondsDiv16)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// ── Disc 126 — update_rule_fhe_gated_authorities (C2 audit fix) ───────────

type UpdateRuleFheGatedAuthoritiesParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	// NewAuthorities is the full canonical 128-byte slot (4 × 32). Unused
	// trailing slots MUST be zero — `NewCount` declares how many are live.
	NewCount          uint8
	NewAuthorities    [MaxFheAuthorities * 32]byte
}

func UpdateRuleFheGatedAuthorities(p UpdateRuleFheGatedAuthoritiesParams) (solana.Instruction, error) {
	if p.NewCount == 0 || int(p.NewCount) > MaxFheAuthorities {
		return nil, fmt.Errorf("policy: fhe authorities count %d out of [1..=%d]",
			p.NewCount, MaxFheAuthorities)
	}
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindFheGated, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+1+MaxFheAuthorities*32)
	data = append(data, DiscUpdateRuleFheGatedAuthorities)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.NewCount)
	data = append(data, p.NewAuthorities[:]...)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// FheGatedConfigHash recomputes the canonical config_hash mirrored by the
// on-chain `add_rule_fhe_gated` / `update_rule_fhe_gated_authorities` handlers.
// Used to bind the challenge produced by `OpTagUpdateFheAuth` to the new state.
func FheGatedConfigHash(
	appliesTo, count, freshnessDiv16 uint8,
	authoritiesFlat [MaxFheAuthorities * 32]byte,
) [32]byte {
	h := sha256.New()
	h.Write([]byte("fhe-gated-config-v1"))
	h.Write([]byte{appliesTo, count, freshnessDiv16})
	h.Write(authoritiesFlat[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
