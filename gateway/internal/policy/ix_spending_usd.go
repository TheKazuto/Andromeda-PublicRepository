package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Update 3 — USD spending limit (KIND_SPENDING_USD) instruction builders.
//
// Mirror of contracts/policy-engine/src/lib.rs:
//   - disc 18: add_rule_spending_usd (creates the rule, feeds_count = 0)
//   - disc 19: update_rule_spending_usd_add_feed (appends one asset)
const (
	DiscAddRuleSpendingUsd           uint8 = 18
	DiscUpdateRuleSpendingUsdAddFeed uint8 = 19
)

// Spending feed layout (mirror of lib.rs `SPENDING_USD_FEED_BYTES` /
// `MAX_SPENDING_USD_FEEDS`). Each entry: feed_cache_account (32) + decimals (1).
const (
	SpendingUsdFeedBytes = 33
	MaxSpendingUsdFeeds  = 16
)

// ── disc 18 — add_rule_spending_usd ─────────────────────────────────────────

type AddRuleSpendingUsdParams struct {
	ProgramID             solana.PublicKey
	Engine                solana.PublicKey
	DWallet               solana.PublicKey
	Payer                 solana.PublicKey
	InitAuthorityHash     [32]byte
	ExpectedNonce         uint64
	RuleIndex             uint8
	AppliesTo             uint8
	FreshnessSecondsDiv16 uint8
	MaxConfidenceBpsDiv4  uint8
	// USD ceilings (canonical 1e8). 0 disables the corresponding window.
	MaxPerTxUsd   uint64
	MaxPerDayUsd  uint64
	MaxPerWeekUsd uint64
}

func AddRuleSpendingUsd(p AddRuleSpendingUsdParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindSpendingUsd, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+1+1+1+8+8+8)
	data = append(data, DiscAddRuleSpendingUsd)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo, p.FreshnessSecondsDiv16, p.MaxConfidenceBpsDiv4)
	binary.LittleEndian.PutUint64(b[:], p.MaxPerTxUsd)
	data = append(data, b[:]...)
	binary.LittleEndian.PutUint64(b[:], p.MaxPerDayUsd)
	data = append(data, b[:]...)
	binary.LittleEndian.PutUint64(b[:], p.MaxPerWeekUsd)
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

// ── disc 19 — update_rule_spending_usd_add_feed ─────────────────────────────

type UpdateRuleSpendingUsdAddFeedParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	// FeedCacheAccount is the Pyth adapter FeedCache PDA for the asset. Passed
	// both as an instruction arg and as a read-only account (the on-chain
	// handler checks its owner against ALLOWED_ORACLE_OWNERS).
	FeedCacheAccount [32]byte
	// Decimals is the asset's base-unit decimal count (SOL=9, USDC=6, …).
	Decimals uint8
}

func UpdateRuleSpendingUsdAddFeed(p UpdateRuleSpendingUsdAddFeedParams) (solana.Instruction, error) {
	if p.Decimals > 24 {
		return nil, fmt.Errorf("policy: spending decimals %d > 24", p.Decimals)
	}
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindSpendingUsd, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	feedCache := solana.PublicKeyFromBytes(p.FeedCacheAccount[:])
	data := make([]byte, 0, 1+32+8+1+32+1)
	data = append(data, DiscUpdateRuleSpendingUsdAddFeed)
	data = append(data, p.InitAuthorityHash[:]...)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], p.ExpectedNonce)
	data = append(data, b[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.FeedCacheAccount[:]...)
	data = append(data, p.Decimals)

	// Account order mirrors `UpdateRuleSpendingUsd` (feed_cache after rule_pda,
	// no rent — update path).
	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: feedCache, IsSigner: false, IsWritable: false},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}
