// Typed instruction builders for each `policy-engine` rule kind. Each file
// mirrors the on-chain handler in `contracts/policy-engine/src/lib.rs`.
package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Discriminators (mirror of contracts/policy-engine/src/lib.rs).
const (
	DiscAddRuleAllowlist                     uint8 = 10
	DiscRequestSignature                     uint8 = 1
	DiscUpdateRuleAllowlistAddDestination    uint8 = 120
	DiscUpdateRuleAllowlistRemoveDestination uint8 = 121
)

// SystemProgramID is the Solana system program (used for `init` accounts).
var SystemProgramID = solana.SystemProgramID

// SysvarInstructions / SysvarClock / SysvarRent — standard Solana sysvars.
var (
	SysvarInstructions = solana.MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111")
	SysvarClock        = solana.MustPublicKeyFromBase58("SysvarC1ock11111111111111111111111111111111")
	SysvarRent         = solana.MustPublicKeyFromBase58("SysvarRent111111111111111111111111111111111")
)

// EventAuthorityPDA derives the Quasar-canonical event authority PDA for a
// given program. Seeds: [b"__event_authority"].
func EventAuthorityPDA(programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{[]byte("__event_authority")}, programID)
}

// AddRuleAllowlistParams carries every typed input for the `add_rule_allowlist`
// instruction (disc 10). PE-011: this carries only minimal config; destinations
// are added later via UpdateRuleAllowlistAddDestination (disc 120).
type AddRuleAllowlistParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	AppliesTo         uint8 // policy.AppliesNormal / Recovery / Session bitmask
}

// AddRuleAllowlist constructs the `add_rule_allowlist` instruction. The caller
// is responsible for assembling and signing the transaction; this function
// only produces the typed `solana.Instruction`.
func AddRuleAllowlist(p AddRuleAllowlistParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindAllowlist, p.RuleIndex)
	if err != nil {
		return nil, fmt.Errorf("derive rule pda: %w", err)
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	data := make([]byte, 0, 1+32+8+1+1)
	data = append(data, DiscAddRuleAllowlist)
	data = append(data, p.InitAuthorityHash[:]...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], p.ExpectedNonce)
	data = append(data, nonce[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.AppliesTo)

	accounts := solana.AccountMetaSlice{
		// Order mirrors the AddRuleAllowlist struct in lib.rs.
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
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// UpdateRuleAllowlistAddDestinationParams — disc 120.
type UpdateRuleAllowlistAddDestinationParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	Destination       [32]byte
}

func UpdateRuleAllowlistAddDestination(p UpdateRuleAllowlistAddDestinationParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindAllowlist, p.RuleIndex)
	if err != nil {
		return nil, fmt.Errorf("derive rule pda: %w", err)
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	data := make([]byte, 0, 1+32+8+1+32)
	data = append(data, DiscUpdateRuleAllowlistAddDestination)
	data = append(data, p.InitAuthorityHash[:]...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], p.ExpectedNonce)
	data = append(data, nonce[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.Destination[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// RequestSignatureParams — disc 1, normal path (PATH_NORMAL).
//
// F8a: `RulePDAs` carries one sub-PDA per active rule slot, in ascending slot
// order (slot 0 first, then slot 1, etc.). These travel as trailing
// `remaining_accounts` in the SVM input. Empty/disabled slots must be skipped.
// Each PDA is attached as writable so kinds with mutable counters (Velocity,
// SessionKey, Recovery) can write back via `data_ptr()`.
type RequestSignatureParams struct {
	ProgramID       solana.PublicKey
	Engine          solana.PublicKey
	DWallet         solana.PublicKey
	Coordinator     solana.PublicKey
	MessageApproval solana.PublicKey
	Payer           solana.PublicKey
	CPIAuthority    solana.PublicKey
	CallerProgram   solana.PublicKey
	DWalletProgram  solana.PublicKey
	RulePDAs        []solana.PublicKey // ordered by active slot, ascending.
	// RuleAux carries the auxiliary read-only accounts that the dispatch
	// consumes immediately AFTER each sub-PDA, indexed parallel to RulePDAs.
	// For KIND_ORACLE: `RuleAux[i]` = one FeedCache PDA per feed, in
	// `feeds_flat` order. For kinds with no aux (Allowlist/Velocity/TimeLock/
	// FheGated) leave it nil/empty. Passkey would carry 2 aux per credential.
	RuleAux             [][]solana.PublicKey
	InitAuthorityHash   [32]byte
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	CPIAuthorityBump    uint8
	Destination         [32]byte
	RulesGenerationSeen uint32
	// Update 3 (ABI V2): asset amount (base units) + index in the active
	// KIND_SPENDING_USD allowlist. Bound into the metadata_digest the caller
	// signs. 0/0 when no spending rule is active.
	Amount     uint64
	AssetIndex uint8
	// Update 6 (ABI V3): the Ika message_metadata_digest forwarded to
	// approve_message. Zero (the default) for every chain without signing
	// metadata — reproduces the prior behaviour. Non-zero for Zcash
	// (keccak256 of the BCS Blake2bMessageMetadata); the MessageApproval PDA
	// MUST then be derived with the matching metadata seed (see MessageApprovalPDA).
	IkaMsgMetadataDigest [32]byte
	// Update 7 (2026-05-26): SWAP clear-signing extension. SigningKind selects
	// which clear-signing renderer + metadata digest variant is used at challenge
	// time. SigningKindNormal (0) keeps the legacy NORMAL path and forces every
	// swap_* field to zero. SigningKindSwap (1) requires the two token addresses
	// to differ and the chain tag to be non-zero.
	SigningKind       uint8
	SwapFromToken     [32]byte
	SwapToToken       [32]byte
	SwapMinAmountOut  uint64
	SwapChainTag      [8]byte // ASCII null-padded ("solana\x00\x00", "evm:1\x00\x00\x00")
	// Update 7 (2026-05-26): BUNDLE challenge extension. When BundleTotal>=2,
	// a single owner signature covers `BundleTotal` distinct request_signature
	// legs (e.g. EVM 2-step approve+swap). This leg sits at `BundleThisIndex`;
	// the other legs' metadata digests are in BundleOtherDigest1..3 in supplied
	// order (trailing slots MUST be zero). BundleTotal=0 keeps the legacy
	// single-digest behaviour.
	BundleTotal         uint8
	BundleThisIndex     uint8
	BundleOtherDigest1  [32]byte
	BundleOtherDigest2  [32]byte
	BundleOtherDigest3  [32]byte
}

func RequestSignature(p RequestSignatureParams) (solana.Instruction, error) {
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	// Capacity covers: disc(1) + init_authority(32) + message_digest(32) +
	// metadata_digest(32) + user_pubkey(32) + scheme(2) + bumps(2) +
	// destination(32) + rules_gen(4) + amount(8) + asset_index(1) +
	// ika_metadata(32) + Update 7 extras: signing_kind(1) + swap_from(32) +
	// swap_to(32) + swap_min_out(8) + chain_tag(8) + bundle_total(1) +
	// bundle_this_index(1) + 3*bundle_other_digest(96) = 389 bytes.
	data := make([]byte, 0, 389)
	data = append(data, DiscRequestSignature)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.MessageDigest[:]...)
	data = append(data, p.MetadataDigest[:]...)
	data = append(data, p.UserPubkey[:]...)
	var scheme [2]byte
	binary.LittleEndian.PutUint16(scheme[:], p.SignatureScheme)
	data = append(data, scheme[:]...)
	data = append(data, p.MessageApprovalBump, p.CPIAuthorityBump)
	data = append(data, p.Destination[:]...)
	var gen [4]byte
	binary.LittleEndian.PutUint32(gen[:], p.RulesGenerationSeen)
	data = append(data, gen[:]...)
	// ABI V2 (Update 3): amount (u64 LE) + asset_index (u8).
	var amt [8]byte
	binary.LittleEndian.PutUint64(amt[:], p.Amount)
	data = append(data, amt[:]...)
	data = append(data, p.AssetIndex)
	// ABI V3 (Update 6): the Ika message_metadata_digest (32 bytes; zero = none).
	data = append(data, p.IkaMsgMetadataDigest[:]...)
	// Update 7 (2026-05-26): SWAP clear-signing + BUNDLE challenge extension.
	// Order MUST match the on-chain handler's parameter order
	// (contracts/policy-engine/src/lib.rs::request_signature): signing_kind,
	// swap_from_token, swap_to_token, swap_min_amount_out, swap_chain_tag,
	// bundle_total, bundle_this_index, bundle_other_digest_{1,2,3}.
	data = append(data, p.SigningKind)
	data = append(data, p.SwapFromToken[:]...)
	data = append(data, p.SwapToToken[:]...)
	var minOut [8]byte
	binary.LittleEndian.PutUint64(minOut[:], p.SwapMinAmountOut)
	data = append(data, minOut[:]...)
	data = append(data, p.SwapChainTag[:]...)
	data = append(data, p.BundleTotal)
	data = append(data, p.BundleThisIndex)
	data = append(data, p.BundleOtherDigest1[:]...)
	data = append(data, p.BundleOtherDigest2[:]...)
	data = append(data, p.BundleOtherDigest3[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: p.Coordinator, IsSigner: false, IsWritable: false},
		{PublicKey: p.MessageApproval, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: p.CPIAuthority, IsSigner: false, IsWritable: false},
		{PublicKey: p.CallerProgram, IsSigner: false, IsWritable: false},
		{PublicKey: p.DWalletProgram, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	// F8a: trailing remaining_accounts — one writable account per active rule
	// slot, in ascending order. F5b/F6b/F7b extend this contract with auxiliary
	// readonly accounts following each slot that needs them (Oracle: 1 aux
	// per feed; Passkey: 2 aux — auth_data + cdj; FheGated: none). Callers
	// stitch them into `RulePDAs` in the correct order.
	// Per active slot: the sub-PDA (writable, so mutating kinds can write back)
	// immediately followed by that slot's auxiliary read-only accounts. This
	// interleaving mirrors the on-chain dispatch, which pulls the sub-PDA from
	// remaining_accounts and then, for KIND_ORACLE, one aux (FeedCache) per
	// feed before advancing to the next slot. Verified byte-for-byte against
	// the SBF dispatch (sub-PDA `new(rule_pda)` + feed `new_readonly`).
	for i, pda := range p.RulePDAs {
		accounts = append(accounts, &solana.AccountMeta{PublicKey: pda, IsSigner: false, IsWritable: true})
		if i < len(p.RuleAux) {
			for _, aux := range p.RuleAux[i] {
				accounts = append(accounts, &solana.AccountMeta{PublicKey: aux, IsSigner: false, IsWritable: false})
			}
		}
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}
