package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Zero-copy decoders for PolicyEngine v3 account state. Layouts mirror
// `contracts/policy-engine/src/lib.rs` and `docs/POLICY_ENGINE_ABI_V3.md` §3.

// ─── PolicyEngine header (ABI §3.1) ──────────────────────────────────────────

// PolicyEngineState is the decoded view of a `PolicyEngine` PDA. Sizes and
// offsets match the byte layout in the on-chain handler.
type PolicyEngineState struct {
	AccountDiscriminator    uint8
	Version                 uint8
	DWallet                 solana.PublicKey
	InitAuthoritySlot       [MemberSlotLen]byte
	OwnerSlot               [MemberSlotLen]byte
	NextAdminNonce          uint64
	NextPrimaryRecoverNonce uint64
	NextQuorumSessionNonce  uint64
	NextOidcSessionNonce    uint64
	NextPasskeySessionNonce uint64
	Paused                  uint8
	RulesCount              uint8
	RulesGeneration         uint32
	Rules                   [MaxRules]RuleEntryView
}

// RuleEntryView is the decoded form of one slot in `PolicyEngine.rules_flat`.
type RuleEntryView struct {
	Kind       RuleKind
	Bump       uint8
	Version    uint8
	Enabled    bool
	Generation uint32
	RulePDA    solana.PublicKey
	ConfigHash [32]byte
}

const (
	policyEngineMinBytes = 1 + 1 + 32 + MemberSlotLen + MemberSlotLen +
		5*8 + 1 + 1 + 4 + 6 /* pad */ + MaxRules*ruleEntryBytes + 8 /* tail */
	ruleEntryBytes = 96
)

// DecodePolicyEngine parses the raw account data of a `PolicyEngine` PDA.
// Returns an error if the discriminator, version, or length don't match.
func DecodePolicyEngine(data []byte) (*PolicyEngineState, error) {
	if len(data) < policyEngineMinBytes {
		return nil, fmt.Errorf("policy: account data too short (%d < %d)", len(data), policyEngineMinBytes)
	}
	if data[0] != 1 {
		return nil, fmt.Errorf("policy: account discriminator = %d (expected 1)", data[0])
	}
	out := &PolicyEngineState{
		AccountDiscriminator: data[0],
		Version:              data[1],
	}
	if out.Version != 1 {
		return nil, fmt.Errorf("policy: unknown PolicyEngine layout version = %d", out.Version)
	}
	copy(out.DWallet[:], data[2:34])
	copy(out.InitAuthoritySlot[:], data[34:68])
	copy(out.OwnerSlot[:], data[68:102])
	out.NextAdminNonce = binary.LittleEndian.Uint64(data[102:110])
	out.NextPrimaryRecoverNonce = binary.LittleEndian.Uint64(data[110:118])
	out.NextQuorumSessionNonce = binary.LittleEndian.Uint64(data[118:126])
	out.NextOidcSessionNonce = binary.LittleEndian.Uint64(data[126:134])
	out.NextPasskeySessionNonce = binary.LittleEndian.Uint64(data[134:142])
	out.Paused = data[142]
	out.RulesCount = data[143]
	out.RulesGeneration = binary.LittleEndian.Uint32(data[144:148])
	// 148..154 is 6-byte pad. Rules start at 154.
	for i := 0; i < MaxRules; i++ {
		off := 154 + i*ruleEntryBytes
		out.Rules[i] = decodeRuleEntry(data[off : off+ruleEntryBytes])
	}
	return out, nil
}

func decodeRuleEntry(b []byte) RuleEntryView {
	var pda solana.PublicKey
	copy(pda[:], b[8:40])
	var hash [32]byte
	copy(hash[:], b[40:72])
	return RuleEntryView{
		Kind:       RuleKind(b[0]),
		Bump:       b[1],
		Version:    b[2],
		Enabled:    b[3] == 1,
		Generation: binary.LittleEndian.Uint32(b[4:8]),
		RulePDA:    pda,
		ConfigHash: hash,
	}
}

// ─── AllowlistRule (ABI §3.4 header + §3.5.1 config) ────────────────────────

// AllowlistRuleState is the decoded view of an `AllowlistRule` sub-PDA.
type AllowlistRuleState struct {
	// Common header.
	AccountDiscriminator uint8
	Kind                 RuleKind
	Index                uint8
	Enabled              bool
	Generation           uint32
	ConfigVersion        uint32
	Engine               solana.PublicKey
	NextAdminNonce       uint64
	ConfigHash           [32]byte
	// Allowlist config.
	AppliesTo         uint8
	DestinationsCount uint8
	Destinations      [][32]byte // sliced to DestinationsCount entries
}

const allowlistRuleMinBytes = 1 + 96 + 8 /* applies + count + pad */ + 1024

func DecodeAllowlistRule(data []byte) (*AllowlistRuleState, error) {
	if len(data) < allowlistRuleMinBytes {
		return nil, fmt.Errorf("policy: AllowlistRule data too short (%d < %d)", len(data), allowlistRuleMinBytes)
	}
	if data[0] != 2 {
		return nil, fmt.Errorf("policy: AllowlistRule discriminator = %d (expected 2)", data[0])
	}
	out := &AllowlistRuleState{
		AccountDiscriminator: data[0],
		Kind:                 RuleKind(data[1]),
		Index:                data[2],
		Enabled:              data[3] == 1,
		// data[4..8]: u32 generation packed (with 1-byte _pad0 byte already accounted at offset 4)
		// Actually layout per lib.rs:
		//   0  1   acct_disc
		//   1  1   kind
		//   2  1   index
		//   3  1   enabled
		//   4  4   _pad0 (filled by Quasar) — kept zero
		//   no, wait, lib.rs layout for AllowlistRule:
		//   pub kind: u8,
		//   pub index: u8,
		//   pub enabled: u8,
		//   pub _pad0: u8,
		//   pub generation: u32,
		//   pub config_version: u32,
		//   pub _pad1: [u8; 4],
		//   pub engine: Address,
		//   pub next_admin_nonce: u64,
		//   pub config_hash: [u8; 32],
		//   pub _pad_header_tail: [u8; 8],
		//   pub config_applies_to: u8,
		//   pub destinations_count: u8,
		//   pub _pad_cfg0: [u8; 6],
		//   pub destinations_flat: [u8; 1024],
		// account discriminator = 1 byte before everything (data[0]).
		// So data[5..9] is generation, data[9..13] is config_version, etc.
	}
	out.Generation = binary.LittleEndian.Uint32(data[5:9])
	out.ConfigVersion = binary.LittleEndian.Uint32(data[9:13])
	// data[13..17] is _pad1.
	copy(out.Engine[:], data[17:49])
	out.NextAdminNonce = binary.LittleEndian.Uint64(data[49:57])
	copy(out.ConfigHash[:], data[57:89])
	// data[89..97] is _pad_header_tail.
	out.AppliesTo = data[97]
	out.DestinationsCount = data[98]
	// data[99..105] is _pad_cfg0.
	out.Destinations = make([][32]byte, 0, out.DestinationsCount)
	for i := 0; i < int(out.DestinationsCount); i++ {
		off := 105 + i*32
		var d [32]byte
		copy(d[:], data[off:off+32])
		out.Destinations = append(out.Destinations, d)
	}
	return out, nil
}
