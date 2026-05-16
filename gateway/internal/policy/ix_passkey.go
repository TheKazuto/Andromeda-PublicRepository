package policy

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Discriminators for F9d (passkey recovery — Secp256r1 + WebAuthn).
const (
	DiscPasskeySessionOpen              uint8 = 89
	DiscRecoverAsPrimaryPasskeySession  uint8 = 90
	DiscPasskeySessionClose             uint8 = 91
)

// WebAuthn payload caps (mirror lib.rs).
const (
	WebAuthnAuthDataMax        = 192
	WebAuthnClientDataJSONMax  = 192
)

// SeedPasskeySession — mirror of `SEED_PASSKEY_SESSION` in lib.rs.
var SeedPasskeySession = []byte("passkey_session")

// PasskeySessionPDA — seeds: [b"passkey_session", engine, nonce_u64_le].
func PasskeySessionPDA(
	programID, engine solana.PublicKey,
	passkeySessionNonce uint64,
) (solana.PublicKey, uint8, error) {
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], passkeySessionNonce)
	return solana.FindProgramAddress(
		[][]byte{SeedPasskeySession, engine.Bytes(), nonce[:]},
		programID,
	)
}

// ── Disc 89 — passkey_session_open ────────────────────────────────────────

type PasskeySessionOpenParams struct {
	ProgramID                      solana.PublicKey
	Engine                         solana.PublicKey
	DWallet                        solana.PublicKey
	Payer                          solana.PublicKey
	InitAuthorityHash              [32]byte
	RuleIndex                      uint8
	PasskeySessionNonce            uint64
	EphPk                          [32]byte
	NotAfterUnixTs                 uint64
	CredentialIdHash               [32]byte
	ExpectedPasskeySessionNonce    uint64
	WebAuthnAuthData               []byte // length-prefixed; padded to WebAuthnAuthDataMax
	WebAuthnClientDataJSON         []byte // length-prefixed; padded to WebAuthnClientDataJSONMax
}

func PasskeySessionOpen(p PasskeySessionOpenParams) (solana.Instruction, error) {
	if len(p.WebAuthnAuthData) == 0 || len(p.WebAuthnAuthData) > WebAuthnAuthDataMax {
		return nil, fmt.Errorf("policy: webauthn_auth_data length %d out of [1..=%d]",
			len(p.WebAuthnAuthData), WebAuthnAuthDataMax)
	}
	if len(p.WebAuthnClientDataJSON) == 0 || len(p.WebAuthnClientDataJSON) > WebAuthnClientDataJSONMax {
		return nil, fmt.Errorf("policy: webauthn_client_data_json length %d out of [1..=%d]",
			len(p.WebAuthnClientDataJSON), WebAuthnClientDataJSONMax)
	}
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, p.RuleIndex)
	if err != nil {
		return nil, err
	}
	sessionPDA, _, err := PasskeySessionPDA(p.ProgramID, p.Engine, p.PasskeySessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}

	authPadded := make([]byte, WebAuthnAuthDataMax)
	copy(authPadded, p.WebAuthnAuthData)
	cdjPadded := make([]byte, WebAuthnClientDataJSONMax)
	copy(cdjPadded, p.WebAuthnClientDataJSON)

	data := make([]byte, 0,
		1+32+1+8+32+8+32+8+2+WebAuthnAuthDataMax+2+WebAuthnClientDataJSONMax)
	data = append(data, DiscPasskeySessionOpen)
	data = append(data, p.InitAuthorityHash[:]...)
	data = append(data, p.RuleIndex)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.PasskeySessionNonce)
	data = append(data, b8[:]...)
	data = append(data, p.EphPk[:]...)
	binary.LittleEndian.PutUint64(b8[:], p.NotAfterUnixTs)
	data = append(data, b8[:]...)
	data = append(data, p.CredentialIdHash[:]...)
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedPasskeySessionNonce)
	data = append(data, b8[:]...)
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], uint16(len(p.WebAuthnAuthData)))
	data = append(data, b2[:]...)
	data = append(data, authPadded...)
	binary.LittleEndian.PutUint16(b2[:], uint16(len(p.WebAuthnClientDataJSON)))
	data = append(data, b2[:]...)
	data = append(data, cdjPadded...)

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

// ── Disc 90 — recover_as_primary_passkey_session ─────────────────────────

type RecoverAsPrimaryPasskeySessionParams struct {
	ProgramID            solana.PublicKey
	Engine               solana.PublicKey
	DWallet              solana.PublicKey
	Coordinator          solana.PublicKey
	MessageApproval      solana.PublicKey
	Payer                solana.PublicKey
	CPIAuthority         solana.PublicKey
	CallerProgram        solana.PublicKey
	DWalletProgram       solana.PublicKey
	InitAuthorityHash    [32]byte
	PasskeySessionNonce  uint64
	MessageDigest        [32]byte
	MetadataDigest       [32]byte
	UserPubkey           [32]byte
	SignatureScheme      uint16
	MessageApprovalBump  uint8
	CPIAuthorityBump     uint8
	ExpectedUseNonce     uint64
}

func RecoverAsPrimaryPasskeySession(p RecoverAsPrimaryPasskeySessionParams) (solana.Instruction, error) {
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindRecovery, 0)
	if err != nil {
		return nil, err
	}
	sessionPDA, _, err := PasskeySessionPDA(p.ProgramID, p.Engine, p.PasskeySessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8+32+32+32+2+1+1+8)
	data = append(data, DiscRecoverAsPrimaryPasskeySession)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.PasskeySessionNonce)
	data = append(data, b8[:]...)
	data = append(data, p.MessageDigest[:]...)
	data = append(data, p.MetadataDigest[:]...)
	data = append(data, p.UserPubkey[:]...)
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], p.SignatureScheme)
	data = append(data, b2[:]...)
	data = append(data, p.MessageApprovalBump, p.CPIAuthorityBump)
	binary.LittleEndian.PutUint64(b8[:], p.ExpectedUseNonce)
	data = append(data, b8[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: false},
		{PublicKey: sessionPDA, IsSigner: false, IsWritable: true},
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

// ── Disc 91 — passkey_session_close ──────────────────────────────────────

type PasskeySessionCloseParams struct {
	ProgramID            solana.PublicKey
	Engine               solana.PublicKey
	DWallet              solana.PublicKey
	Recipient            solana.PublicKey // signs + receives rent (must == payer_for_close)
	InitAuthorityHash    [32]byte
	PasskeySessionNonce  uint64
}

func PasskeySessionClose(p PasskeySessionCloseParams) (solana.Instruction, error) {
	sessionPDA, _, err := PasskeySessionPDA(p.ProgramID, p.Engine, p.PasskeySessionNonce)
	if err != nil {
		return nil, err
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+32+8)
	data = append(data, DiscPasskeySessionClose)
	data = append(data, p.InitAuthorityHash[:]...)
	var b8 [8]byte
	binary.LittleEndian.PutUint64(b8[:], p.PasskeySessionNonce)
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
