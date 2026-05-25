package policy

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/gagliardetto/solana-go"
)

// Discriminators for F8b/F8c (SessionKey rule + ephemeral session lifecycle).
const (
	DiscAddRuleSessionKey          uint8 = 16
	DiscSessionOpen                uint8 = 100
	DiscRequestSignatureViaSession uint8 = 101
	DiscSessionRevoke              uint8 = 102
	DiscSessionClose               uint8 = 103
	DiscCloseExpiredSession        uint8 = 104
	DiscSessionAddDestination      uint8 = 105
	DiscSessionRemoveDestination   uint8 = 106
)

// SessionMaxDestinations is the per-session destination allowlist cap (F8c).
// Mirrors lib.rs `SESSION_MAX_DESTINATIONS`.
const SessionMaxDestinations = 8

// ── F8b — add_rule_session_key (disc 16) ───────────────────────────────────

// AddRuleSessionKeyParams — disc 16.
//
// AppliesTo MUST equal AppliesSession (=4). Other masks are rejected on-chain.
type AddRuleSessionKeyParams struct {
	ProgramID             solana.PublicKey
	Engine                solana.PublicKey
	DWallet               solana.PublicKey
	Payer                 solana.PublicKey
	InitAuthorityHash     [32]byte
	ExpectedNonce         uint64
	RuleIndex             uint8
	AppliesTo             uint8
	MaxSessions           uint8
	DefaultTTLSeconds     uint64
	DefaultMaxUses        uint32
	SessionMaxAmountPerTx uint64
}

func AddRuleSessionKey(p AddRuleSessionKeyParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindSessionKey, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, 1+32+8+1+1+1+8+4+8)
	data = append(data, DiscAddRuleSessionKey)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	data = append(data, p.RuleIndex, p.AppliesTo, p.MaxSessions)
	binary.LittleEndian.PutUint64(b8[:], p.DefaultTTLSeconds)
	data = append(data, b8[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.DefaultMaxUses)
	data = append(data, b4[:]...)
	binary.LittleEndian.PutUint64(b8[:], p.SessionMaxAmountPerTx)
	data = append(data, b8[:]...)

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

// SessionKeyConfigHash — canonical hash of the SessionKey rule config.
// Domain string: `b"session-key-config-v1"`. Mirrors lib.rs lines around the
// `b"session-key-config-v1"` literal.
func SessionKeyConfigHash(
	appliesTo, maxSessions uint8,
	defaultTTLSeconds uint64,
	defaultMaxUses uint32,
	sessionMaxAmountPerTx uint64,
) [32]byte {
	h := sha256.New()
	h.Write([]byte("session-key-config-v1"))
	h.Write([]byte{appliesTo, maxSessions})
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], defaultTTLSeconds)
	h.Write(b8[:])
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], defaultMaxUses)
	h.Write(b4[:])
	binary.LittleEndian.PutUint64(b8[:], sessionMaxAmountPerTx)
	h.Write(b8[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ── F8b — session_open (disc 100) ─────────────────────────────────────────

type SessionOpenParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	SessionIndex      uint32
	SessionSigner     solana.PublicKey
	ExpiresAtTs       int64
	MaxUses           uint32
	MaxAmountPerTx    uint64
}

func SessionOpen(p SessionOpenParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindSessionKey, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	sessionPDA, _, err := SessionPDA(p.ProgramID, p.Engine, p.SessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, 1+32+8+1+4+32+8+4+8)
	data = append(data, DiscSessionOpen)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	data = append(data, p.RuleIndex)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.SessionIndex)
	data = append(data, b4[:]...)
	data = append(data, p.SessionSigner.Bytes()...)
	binary.LittleEndian.PutUint64(b8[:], uint64(p.ExpiresAtTs))
	data = append(data, b8[:]...)
	binary.LittleEndian.PutUint32(b4[:], p.MaxUses)
	data = append(data, b4[:]...)
	binary.LittleEndian.PutUint64(b8[:], p.MaxAmountPerTx)
	data = append(data, b8[:]...)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: false},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}, data), nil
}

// ── F8b — request_signature_via_session (disc 101) ────────────────────────

// RequestSignatureViaSessionParams — disc 101.
//
// `SessionSigner` MUST be the keypair recorded at `session_open`. The
// session keypair signs natively here; the gas sponsor (Payer) covers fees.
type RequestSignatureViaSessionParams struct {
	ProgramID              solana.PublicKey
	Engine                 solana.PublicKey
	DWallet                solana.PublicKey
	Coordinator            solana.PublicKey
	MessageApproval        solana.PublicKey
	Payer                  solana.PublicKey
	CPIAuthority           solana.PublicKey
	CallerProgram          solana.PublicKey
	DWalletProgram         solana.PublicKey
	SessionSigner          solana.PublicKey
	InitAuthorityHash      [32]byte
	SessionIndex           uint32
	MessageDigest          [32]byte
	MetadataDigest         [32]byte
	UserPubkey             [32]byte
	SignatureScheme        uint16
	MessageApprovalBump    uint8
	CPIAuthorityBump       uint8
	Destination            [32]byte
	ExpectedSignatureNonce uint64
}

func RequestSignatureViaSession(p RequestSignatureViaSessionParams) (solana.Instruction, error) {
	sessionPDA, _, err := SessionPDA(p.ProgramID, p.Engine, p.SessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, 1+32+4+32+32+32+2+1+1+32+8)
	data = append(data, DiscRequestSignatureViaSession)
	data = append(data, p.InitAuthorityHash[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.SessionIndex)
	data = append(data, b4[:]...)
	data = append(data, p.MessageDigest[:]...)
	data = append(data, p.MetadataDigest[:]...)
	data = append(data, p.UserPubkey[:]...)
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], p.SignatureScheme)
	data = append(data, b2[:]...)
	data = append(data, p.MessageApprovalBump, p.CPIAuthorityBump)
	data = append(data, p.Destination[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedSignatureNonce)
	data = append(data, b8[:]...)

	return solana.NewInstruction(p.ProgramID, solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.SessionSigner, IsSigner: true, IsWritable: false},
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
	}, data), nil
}

// ── F8c — session lifecycle (revoke / close / cleanup / dest updates) ──────

// sessionAdminAccounts builds the account list shared by SessionRevoke,
// SessionAddDestination, SessionRemoveDestination (no recipient slot).
func sessionAdminAccounts(
	programID, dwallet, engine, session, payer solana.PublicKey,
	eventAuth solana.PublicKey,
) solana.AccountMetaSlice {
	return solana.AccountMetaSlice{
		{PublicKey: dwallet, IsSigner: false, IsWritable: false},
		{PublicKey: engine, IsSigner: false, IsWritable: true},
		{PublicKey: session, IsSigner: false, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: payer, IsSigner: true, IsWritable: true},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: programID, IsSigner: false, IsWritable: false},
	}
}

// sessionCloseAccounts builds the account list shared by SessionClose and
// CloseExpiredSession (recipient slot present).
func sessionCloseAccounts(
	programID, dwallet, engine, session, recipient, payer solana.PublicKey,
	eventAuth solana.PublicKey,
) solana.AccountMetaSlice {
	return solana.AccountMetaSlice{
		{PublicKey: dwallet, IsSigner: false, IsWritable: false},
		{PublicKey: engine, IsSigner: false, IsWritable: true},
		{PublicKey: session, IsSigner: false, IsWritable: true},
		{PublicKey: recipient, IsSigner: false, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: payer, IsSigner: true, IsWritable: true},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: programID, IsSigner: false, IsWritable: false},
	}
}

// SessionRevokeParams — disc 102. Force-expires the session ().
type SessionRevokeParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
	ExpectedNonce     uint64
}

func SessionRevoke(p SessionRevokeParams) (solana.Instruction, error) {
	session, _, err := SessionPDA(p.ProgramID, p.Engine, p.SessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+4+8)
	data = append(data, DiscSessionRevoke)
	data = append(data, p.InitAuthorityHash[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.SessionIndex)
	data = append(data, b4[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	return solana.NewInstruction(p.ProgramID,
		sessionAdminAccounts(p.ProgramID, p.DWallet, p.Engine, session, p.Payer, eventAuth),
		data,
	), nil
}

// SessionCloseParams — disc 103. Closes Session PDA, rent → recipient (bound
// into challenge). Caller MUST sign with owner; recipient cannot be redirected.
type SessionCloseParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	Recipient         solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
	ExpectedNonce     uint64
}

func SessionClose(p SessionCloseParams) (solana.Instruction, error) {
	session, _, err := SessionPDA(p.ProgramID, p.Engine, p.SessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+4+8)
	data = append(data, DiscSessionClose)
	data = append(data, p.InitAuthorityHash[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.SessionIndex)
	data = append(data, b4[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedNonce)
	data = append(data, b8[:]...)
	return solana.NewInstruction(p.ProgramID,
		sessionCloseAccounts(p.ProgramID, p.DWallet, p.Engine, session, p.Recipient, p.Payer, eventAuth),
		data,
	), nil
}

// CloseExpiredSessionParams — disc 104. Permissionless cleanup post-expiry.
// No nonce/challenge needed; runtime expiry is the gate.
type CloseExpiredSessionParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	Recipient         solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
}

func CloseExpiredSession(p CloseExpiredSessionParams) (solana.Instruction, error) {
	session, _, err := SessionPDA(p.ProgramID, p.Engine, p.SessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+4)
	data = append(data, DiscCloseExpiredSession)
	data = append(data, p.InitAuthorityHash[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], p.SessionIndex)
	data = append(data, b4[:]...)
	return solana.NewInstruction(p.ProgramID,
		sessionCloseAccounts(p.ProgramID, p.DWallet, p.Engine, session, p.Recipient, p.Payer, eventAuth),
		data,
	), nil
}

// SessionAddDestinationParams — disc 105.
type SessionAddDestinationParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
	ExpectedNonce     uint64
	Destination       [32]byte
}

func SessionAddDestination(p SessionAddDestinationParams) (solana.Instruction, error) {
	return buildSessionUpdateDestination(
		DiscSessionAddDestination,
		p.ProgramID, p.Engine, p.DWallet, p.Payer,
		p.InitAuthorityHash, p.SessionIndex, p.ExpectedNonce, p.Destination,
	)
}

// SessionRemoveDestinationParams — disc 106.
type SessionRemoveDestinationParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
	ExpectedNonce     uint64
	Destination       [32]byte
}

func SessionRemoveDestination(p SessionRemoveDestinationParams) (solana.Instruction, error) {
	return buildSessionUpdateDestination(
		DiscSessionRemoveDestination,
		p.ProgramID, p.Engine, p.DWallet, p.Payer,
		p.InitAuthorityHash, p.SessionIndex, p.ExpectedNonce, p.Destination,
	)
}

func buildSessionUpdateDestination(
	disc uint8,
	programID, engine, dwallet, payer solana.PublicKey,
	initAuthorityHash [32]byte,
	sessionIndex uint32,
	expectedNonce uint64,
	destination [32]byte,
) (solana.Instruction, error) {
	session, _, err := SessionPDA(programID, engine, sessionIndex)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(programID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+4+8+32)
	data = append(data, disc)
	data = append(data, initAuthorityHash[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], sessionIndex)
	data = append(data, b4[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], expectedNonce)
	data = append(data, b8[:]...)
	data = append(data, destination[:]...)
	return solana.NewInstruction(programID,
		sessionAdminAccounts(programID, dwallet, engine, session, payer, eventAuth),
		data,
	), nil
}
