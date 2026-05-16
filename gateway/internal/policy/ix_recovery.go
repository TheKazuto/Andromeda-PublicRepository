package policy

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/gagliardetto/solana-go"
)

// Discriminators for F9a (RecoveryRule lifecycle + recover_as_primary path).
const (
	DiscRecoverAsPrimary                  uint8 = 80
	DiscUpdateRecoveryAddMember           uint8 = 130
	DiscUpdateRecoveryRemoveMember        uint8 = 131
	DiscUpdateRecoveryAddDestination      uint8 = 132
	DiscUpdateRecoveryRemoveDestination   uint8 = 133
)

// Recovery rule sizing caps (mirror lib.rs).
const (
	MaxRecoveryMembers      = 16
	MaxRecoveryDestinations = 16
)

// RecoveryConfigHash — canonical hash of the immutable RecoveryRule config.
// Members and destinations are managed as a dynamic roster and are NOT part
// of `config_hash`; lists are hashed as their zero-pad baseline.
func RecoveryConfigHash(
	appliesTo, primaryPresent uint8,
	primarySlot [MemberSlotLen]byte,
	quorumThreshold, dailyLimitPresent uint8,
	dailyLimit uint64,
	cooldownSeconds uint64,
	oidcIssHash [16]byte,
	oidcAudHash [16]byte,
	jwkRegistryAddr solana.PublicKey,
) [32]byte {
	h := sha256.New()
	h.Write([]byte("recovery-config-v1"))
	h.Write([]byte{appliesTo, primaryPresent})
	h.Write(primarySlot[:])
	h.Write([]byte{quorumThreshold, dailyLimitPresent})
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], dailyLimit)
	h.Write(b8[:])
	binary.LittleEndian.PutUint64(b8[:], cooldownSeconds)
	h.Write(b8[:])
	zeroMembers := make([]byte, MaxRecoveryMembers*MemberSlotLen)
	zeroDests := make([]byte, MaxRecoveryDestinations*32)
	h.Write(zeroMembers)
	h.Write(zeroDests)
	h.Write(oidcIssHash[:])
	h.Write(oidcAudHash[:])
	h.Write(jwkRegistryAddr.Bytes())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ── F9a — update_rule_recovery_add_member (disc 130) ────────────────────

func recoveryUpdateAccounts(
	programID, dwallet, engine, rulePDA, payer solana.PublicKey,
	eventAuth solana.PublicKey,
) solana.AccountMetaSlice {
	return solana.AccountMetaSlice{
		{PublicKey: dwallet, IsSigner: false, IsWritable: false},
		{PublicKey: engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: programID, IsSigner: false, IsWritable: false},
	}
}

type UpdateRecoveryAddMemberParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	MemberSlot        [MemberSlotLen]byte
}

func UpdateRecoveryAddMember(p UpdateRecoveryAddMemberParams) (solana.Instruction, error) {
	return buildRecoveryMemberIx(DiscUpdateRecoveryAddMember,
		p.ProgramID, p.Engine, p.DWallet, p.Payer,
		p.InitAuthorityHash, p.ExpectedNonce, p.RuleIndex, p.MemberSlot)
}

type UpdateRecoveryRemoveMemberParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	MemberSlot        [MemberSlotLen]byte
}

func UpdateRecoveryRemoveMember(p UpdateRecoveryRemoveMemberParams) (solana.Instruction, error) {
	return buildRecoveryMemberIx(DiscUpdateRecoveryRemoveMember,
		p.ProgramID, p.Engine, p.DWallet, p.Payer,
		p.InitAuthorityHash, p.ExpectedNonce, p.RuleIndex, p.MemberSlot)
}

func buildRecoveryMemberIx(
	disc uint8,
	programID, engine, dwallet, payer solana.PublicKey,
	initAuthorityHash [32]byte,
	expectedNonce uint64,
	ruleIndex uint8,
	memberSlot [MemberSlotLen]byte,
) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(programID, engine, KindRecovery, ruleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(programID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+MemberSlotLen)
	data = append(data, disc)
	data = append(data, initAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], expectedNonce)
	data = append(data, b8[:]...)
	data = append(data, ruleIndex)
	data = append(data, memberSlot[:]...)
	return solana.NewInstruction(programID,
		recoveryUpdateAccounts(programID, dwallet, engine, rulePDA, payer, eventAuth),
		data,
	), nil
}

// ── F9a — update_rule_recovery_add/remove_destination (132/133) ─────────

type UpdateRecoveryDestinationParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	Destination       [32]byte
}

func UpdateRecoveryAddDestination(p UpdateRecoveryDestinationParams) (solana.Instruction, error) {
	return buildRecoveryDestinationIx(DiscUpdateRecoveryAddDestination, p)
}

func UpdateRecoveryRemoveDestination(p UpdateRecoveryDestinationParams) (solana.Instruction, error) {
	return buildRecoveryDestinationIx(DiscUpdateRecoveryRemoveDestination, p)
}

func buildRecoveryDestinationIx(
	disc uint8,
	p UpdateRecoveryDestinationParams,
) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1+32)
	data = append(data, disc)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.Destination[:]...)
	return solana.NewInstruction(p.ProgramID,
		recoveryUpdateAccounts(p.ProgramID, p.DWallet, p.Engine, rulePDA, p.Payer, eventAuth),
		data,
	), nil
}

// ── F9a — recover_as_primary (disc 80) ───────────────────────────────────

// RecoverAsPrimaryParams — disc 80. Primary keypair signs an Ika
// approve_message off-chain; this builder packs the on-chain call.
type RecoverAsPrimaryParams struct {
	ProgramID              solana.PublicKey
	Engine                 solana.PublicKey
	DWallet                solana.PublicKey
	Coordinator            solana.PublicKey
	MessageApproval        solana.PublicKey
	Payer                  solana.PublicKey
	CPIAuthority           solana.PublicKey
	CallerProgram          solana.PublicKey
	DWalletProgram         solana.PublicKey
	InitAuthorityHash      [32]byte
	RuleIndex              uint8
	MessageDigest          [32]byte
	MetadataDigest         [32]byte
	UserPubkey             [32]byte
	SignatureScheme        uint16
	MessageApprovalBump    uint8
	CPIAuthorityBump       uint8
	Destination            [32]byte
	ExpectedNonce          uint64
	Amount                 uint64
}

func RecoverAsPrimary(p RecoverAsPrimaryParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+1+32+32+32+2+1+1+32+8+8)
	data = append(data, DiscRecoverAsPrimary)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.MessageDigest[:]...)
	data = append(data, p.MetadataDigest[:]...)
	data = append(data, p.UserPubkey[:]...)
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], p.SignatureScheme)
	data = append(data, b2[:]...)
	data = append(data, p.MessageApprovalBump, p.CPIAuthorityBump)
	data = append(data, p.Destination[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	binary.LittleEndian.PutUint64(b8[:], p.Amount)
	data = append(data, b8[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
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
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}
