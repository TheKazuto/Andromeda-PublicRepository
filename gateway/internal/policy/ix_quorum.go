package policy

import (
	"encoding/binary"

	"github.com/gagliardetto/solana-go"
)

// Discriminators for F9b (Quorum recovery — multi-tx M-of-N).
const (
	DiscQuorumSessionOpen       uint8 = 82
	DiscQuorumSessionContribute uint8 = 83
	DiscQuorumSessionFinalize   uint8 = 85
	DiscQuorumSessionClose      uint8 = 86
)

// SeedQuorumSession — mirror of `SEED_QUORUM_SESSION` in lib.rs.
var SeedQuorumSession = []byte("quorum_session")

// QuorumSessionPDA derives the ephemeral PDA used to stage an M-of-N recovery.
// Seeds: [b"quorum_session", engine_pda, session_nonce_u64_le].
func QuorumSessionPDA(
	programID, engine solana.PublicKey,
	sessionNonce uint64,
) (solana.PublicKey, uint8, error) {
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], sessionNonce)
	return solana.FindProgramAddress(
		[][]byte{SeedQuorumSession, engine.Bytes(), nonce[:]},
		programID,
	)
}

// ── Disc 82 — quorum_session_open ─────────────────────────────────────────

// QuorumSessionOpenParams — primary authorizes a new quorum session bound to
// `(message_digest, metadata_digest, amount, destination, expires_at)`.
type QuorumSessionOpenParams struct {
	ProgramID           solana.PublicKey
	Engine              solana.PublicKey
	DWallet             solana.PublicKey
	Payer               solana.PublicKey
	InitAuthorityHash   [32]byte
	RuleIndex           uint8
	SessionNonce        uint64
	MessageDigest       [32]byte
	MetadataDigest      [32]byte
	UserPubkey          [32]byte
	SignatureScheme     uint16
	MessageApprovalBump uint8
	Amount              uint64
	Destination         [32]byte
	ExpiresAt           int64
}

func QuorumSessionOpen(p QuorumSessionOpenParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	sessionPDA, _, err := QuorumSessionPDA(p.ProgramID, p.Engine, p.SessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+1+8+32+32+32+2+1+8+32+8)
	data = append(data, DiscQuorumSessionOpen)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.RuleIndex)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.SessionNonce)
	data = append(data, b8[:]...)
	data = append(data, p.MessageDigest[:]...)
	data = append(data, p.MetadataDigest[:]...)
	data = append(data, p.UserPubkey[:]...)
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], p.SignatureScheme)
	data = append(data, b2[:]...)
	data = append(data, p.MessageApprovalBump)
	binary.LittleEndian.PutUint64(b8[:], p.Amount)
	data = append(data, b8[:]...)
	data = append(data, p.Destination[:]...)
	binary.LittleEndian.PutUint64(b8[:], uint64(p.ExpiresAt))
	data = append(data, b8[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// ── Disc 83 — quorum_session_contribute ──────────────────────────────────

type QuorumSessionContributeParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	SessionNonce      uint64
	MemberIndex       uint8
}

func QuorumSessionContribute(p QuorumSessionContributeParams) (solana.Instruction, error) {
	sessionPDA, _, err := QuorumSessionPDA(p.ProgramID, p.Engine, p.SessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+1)
	data = append(data, DiscQuorumSessionContribute)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.SessionNonce)
	data = append(data, b8[:]...)
	data = append(data, p.MemberIndex)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// ── Disc 85 — quorum_session_finalize ────────────────────────────────────

// QuorumSessionFinalizeParams — `RuleIndex` was added by audit fix H1
// (2026-05-16): the on-chain Accts struct no longer hardcodes `rule_index = 0`.
// Callers MUST pass the same `RuleIndex` used when the session was opened.
type QuorumSessionFinalizeParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Coordinator       solana.PublicKey
	MessageApproval   solana.PublicKey
	Payer             solana.PublicKey
	CPIAuthority      solana.PublicKey
	CallerProgram     solana.PublicKey
	DWalletProgram    solana.PublicKey
	InitAuthorityHash [32]byte
	RuleIndex         uint8
	SessionNonce      uint64
	CPIAuthorityBump  uint8
}

func QuorumSessionFinalize(p QuorumSessionFinalizeParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	sessionPDA, _, err := QuorumSessionPDA(p.ProgramID, p.Engine, p.SessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	// disc + init_authority_hash + rule_index + session_nonce + cpi_authority_bump
	data := make([]byte, 0, 1+32+1+8+1)
	data = append(data, DiscQuorumSessionFinalize)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.RuleIndex)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.SessionNonce)
	data = append(data, b8[:]...)
	data = append(data, p.CPIAuthorityBump)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Coordinator, IsSigner: false, IsWritable: false},
		{PublicKey: p.MessageApproval, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: p.CPIAuthority, IsSigner: false, IsWritable: false},
		{PublicKey: p.CallerProgram, IsSigner: false, IsWritable: false},
		{PublicKey: p.DWalletProgram, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// ── Disc 86 — quorum_session_close ───────────────────────────────────────

// QuorumSessionCloseParams — `Recipient` is the rent destination AND the tx
// signer (no separate payer). MUST equal `session.payer_for_close`, locked in
// at open time.
type QuorumSessionCloseParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Recipient         solana.PublicKey
	InitAuthorityHash [32]byte
	SessionNonce      uint64
}

func QuorumSessionClose(p QuorumSessionCloseParams) (solana.Instruction, error) {
	sessionPDA, _, err := QuorumSessionPDA(p.ProgramID, p.Engine, p.SessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8)
	data = append(data, DiscQuorumSessionClose)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.SessionNonce)
	data = append(data, b8[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: false},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Recipient, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}
