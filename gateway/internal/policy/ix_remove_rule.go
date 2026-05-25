// B1 audit fix (2026-05-25): typed builder for the `remove_rule` instruction
// (disc 110). Mirrors the on-chain handler + `RemoveRule` Accounts struct in
// contracts/policy-engine/src/lib.rs.
package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// DiscRemoveRule is the policy-engine `remove_rule` discriminator.
const DiscRemoveRule uint8 = 110

// RemoveRuleParams carries every typed input for the `remove_rule` instruction.
// The rule sub-PDA is derived by the caller from the rule kind + index; the
// on-chain handler validates it against the recorded RuleEntry before closing it
// (rent → Recipient, which MUST equal the address bound into the owner challenge).
type RemoveRuleParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	RulePDA           solana.PublicKey
	Recipient         solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
}

// RemoveRule constructs the `remove_rule` instruction (disc 110). The account
// order mirrors the `RemoveRule` Accounts struct in lib.rs exactly.
func RemoveRule(p RemoveRuleParams) (solana.Instruction, error) {
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	data := make([]byte, 0, 1+32+8+1)
	data = append(data, DiscRemoveRule)
	data = append(data, p.InitAuthorityHash[:]...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], p.ExpectedNonce)
	data = append(data, nonce[:]...)
	data = append(data, p.RuleIndex)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: p.RulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Recipient, IsSigner: false, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}
