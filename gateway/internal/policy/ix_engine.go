package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Disc 0.
const DiscInitEngine uint8 = 0

// InitEngineParams — disc 0. Builds the canonical `init_engine` instruction.
// F2.6b limitation: `DefaultRecoveryPresent` must be 0 for now — when 1, the
// caller would also need to pass a `rule_recovery_pda` account (planned for F9).
type InitEngineParams struct {
	ProgramID              solana.PublicKey
	DWallet                solana.PublicKey
	Engine                 solana.PublicKey
	Payer                  solana.PublicKey
	InitAuthoritySlot      [MemberSlotLen]byte
	InitAuthorityHash      [32]byte
	OwnerSlot              [MemberSlotLen]byte
	DefaultRecoveryPresent uint8
	DefaultRecoveryHash    [32]byte
}

func InitEngine(p InitEngineParams) (solana.Instruction, error) {
	if p.DefaultRecoveryPresent != 0 {
		return nil, fmt.Errorf("rules.InitEngine: default_recovery_present=1 is F9 scope")
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	data := make([]byte, 0, 1+34+32+34+1+32)
	data = append(data, DiscInitEngine)
	data = append(data, p.InitAuthoritySlot[:]...)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.OwnerSlot[:]...)
	data = append(data, p.DefaultRecoveryPresent)
	data = append(data, p.DefaultRecoveryHash[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
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

// Silences unused import in case binary is dropped during edits.
var _ = binary.LittleEndian
