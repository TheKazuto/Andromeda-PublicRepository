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
}

func RequestSignature(p RequestSignatureParams) (solana.Instruction, error) {
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	data := make([]byte, 0, 1+32+32+32+32+32+2+1+1+32+4)
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
