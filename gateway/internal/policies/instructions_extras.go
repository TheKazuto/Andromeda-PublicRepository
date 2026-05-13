package policies

import (
	"fmt"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
)

// ────────────────────────────────────────────────────────────────
// oracle-conditional
// ────────────────────────────────────────────────────────────────

type OracleInitInput struct {
	InitContext
	OwnerSlot        [auth.MemberSlotLen]byte
	OracleFeed       solana.PublicKey
	MinPrice         int64
	MaxPrice         int64
	MaxAgeSlots      uint64
	MaxConfidenceBps uint16 // Audit M1: 0 = disabled.
}

func BuildOracleInit(reg *Registry, in OracleInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateOracleConditional)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateOracleConditional, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.OracleInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot,
		in.OracleFeed, in.MinPrice, in.MaxPrice, in.MaxAgeSlots, in.MaxConfidenceBps)
	preIx, err := auth.BuildCredentialPrecompile(in.InitAuthoritySlot, challenge,
		in.InitSig.Signature, in.InitSig.WebauthnAuthData, in.InitSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build init precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(0)
	w.Bytes(in.InitAuthoritySlot[:])
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes(in.OwnerSlot[:])
	w.Bytes32(in.OracleFeed)
	w.I64(in.MinPrice)
	w.I64(in.MaxPrice)
	w.U64(in.MaxAgeSlots)
	w.U16(in.MaxConfidenceBps) // Audit M1.
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type OracleAdminAction uint8

const (
	OracleUpdateBounds OracleAdminAction = 2
	OraclePauseAction  OracleAdminAction = 3
	OracleResumeAction OracleAdminAction = 4
)

type OracleAdminInput struct {
	AdminContext
	Action           OracleAdminAction
	MinPrice         int64
	MaxPrice         int64
	MaxAgeSlots      uint64
	MaxConfidenceBps uint16 // Audit M1: only used by OracleUpdateBounds.
	ExpectedNonce    uint64
	OwnerSig         AdminSignature
}

func BuildOracleAdmin(reg *Registry, in OracleAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateOracleConditional)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateOracleConditional, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case OracleUpdateBounds:
		challenge = auth.OracleUpdateBoundsChallenge(in.Dwallet, policyPda, in.MinPrice, in.MaxPrice, in.MaxAgeSlots, in.MaxConfidenceBps, in.ExpectedNonce, in.OwnerSlot)
		w.I64(in.MinPrice)
		w.I64(in.MaxPrice)
		w.U64(in.MaxAgeSlots)
		w.U16(in.MaxConfidenceBps) // Audit M1.
		w.U64(in.ExpectedNonce)
	case OraclePauseAction:
		challenge = auth.OraclePauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case OracleResumeAction:
		challenge = auth.OracleResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid OracleAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type OracleRequestSignatureInput struct {
	RequestSigCommon
	OracleFeed          solana.PublicKey
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
}

func BuildOracleRequestSignature(reg *Registry, in OracleRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateOracleConditional)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	w := &ByteWriter{}
	w.U8(1)
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)

	policyPda, _, err := PolicyPDA(TemplateOracleConditional, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	cpiAuth, _, err := CPIAuthorityPDA(prog)
	if err != nil {
		return nil, err
	}
	msgApproval, _, err := MessageApprovalPDA(
		reg.IkaProgramID,
		in.DwalletCurve, in.DwalletPublicKey,
		in.SignatureScheme,
		in.MessageDigest[:], in.MetaDigest[:],
	)
	if err != nil {
		return nil, err
	}

	// Account order matches the on-chain RequestSignature struct:
	// [dwallet, policy, oracle_feed, coordinator, message_approval, payer,
	//  cpi_authority, caller_program, dwallet_program, clock, system_program]
	return solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(in.OracleFeed, accReadonly),
		meta(reg.IkaCoordinator, accReadonly),
		meta(msgApproval, accWritable),
		meta(in.Sponsor, accWritableSigner),
		meta(cpiAuth, accReadonly),
		meta(prog, accReadonly),
		meta(reg.IkaProgramID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, w.Result()), nil
}

// ────────────────────────────────────────────────────────────────
// passkey-step-up
// ────────────────────────────────────────────────────────────────

type PasskeyInitInput struct {
	InitContext
	OwnerSlot       [auth.MemberSlotLen]byte
	ThresholdAmount uint64
	PasskeyPubkey   [33]byte
}

func BuildPasskeyInit(reg *Registry, in PasskeyInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplatePasskeyStepUp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplatePasskeyStepUp, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.PasskeyInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot,
		in.ThresholdAmount, in.PasskeyPubkey)
	preIx, err := auth.BuildCredentialPrecompile(in.InitAuthoritySlot, challenge,
		in.InitSig.Signature, in.InitSig.WebauthnAuthData, in.InitSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build init precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(0)
	w.Bytes(in.InitAuthoritySlot[:])
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes(in.OwnerSlot[:])
	w.U64(in.ThresholdAmount)
	w.Bytes(in.PasskeyPubkey[:])
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type PasskeyAdminAction uint8

const (
	PasskeyUpdatePolicy PasskeyAdminAction = 2
	PasskeyPauseAction  PasskeyAdminAction = 3
	PasskeyResumeAction PasskeyAdminAction = 4
)

type PasskeyAdminInput struct {
	AdminContext
	Action          PasskeyAdminAction
	ThresholdAmount uint64
	PasskeyPubkey   [33]byte
	ExpectedNonce   uint64
	OwnerSig        AdminSignature
}

func BuildPasskeyAdmin(reg *Registry, in PasskeyAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplatePasskeyStepUp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplatePasskeyStepUp, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case PasskeyUpdatePolicy:
		challenge = auth.PasskeyUpdatePolicyChallenge(in.Dwallet, policyPda, in.ThresholdAmount, in.PasskeyPubkey, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ThresholdAmount)
		w.Bytes(in.PasskeyPubkey[:])
		w.U64(in.ExpectedNonce)
	case PasskeyPauseAction:
		challenge = auth.PasskeyPauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case PasskeyResumeAction:
		challenge = auth.PasskeyResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid PasskeyAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// PasskeyRequestSignatureInput — below-threshold path (disc 1).
type PasskeyRequestSignatureInput struct {
	RequestSigCommon
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
	TxAmount            uint64
}

func BuildPasskeyRequestSignature(reg *Registry, in PasskeyRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplatePasskeyStepUp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	w := &ByteWriter{}
	w.U8(1)
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)
	w.U64(in.TxAmount)
	return buildRequestSig(prog, reg, TemplatePasskeyStepUp, in.RequestSigCommon, w.Result())
}

// PasskeyRequestSignatureStepUpInput — above-threshold path (disc 5). Carries
// the WebAuthn assertion inline; the gateway also injects a Secp256r1
// precompile invocation with `(passkey_pubkey, auth_data || sha256(cdj),
// signature)` ahead of the main ix. Both ix are returned.
type PasskeyRequestSignatureStepUpInput struct {
	RequestSigCommon
	MessageApprovalBump    uint8
	CpiAuthorityBump       uint8
	TxAmount               uint64
	ExpectedStepUpNonce    uint64
	PasskeyPubkey          [33]byte // bound on-chain at init
	WebauthnAuthData       []byte   // ≤64
	WebauthnClientDataJSON []byte   // ≤192
	WebauthnSignature      []byte   // 64 bytes (r||s)
}

func BuildPasskeyRequestSignatureStepUp(reg *Registry, in PasskeyRequestSignatureStepUpInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplatePasskeyStepUp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplatePasskeyStepUp, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	cpiAuth, _, err := CPIAuthorityPDA(prog)
	if err != nil {
		return nil, err
	}
	msgApproval, _, err := MessageApprovalPDA(
		reg.IkaProgramID,
		in.DwalletCurve, in.DwalletPublicKey,
		in.SignatureScheme,
		in.MessageDigest[:], in.MetaDigest[:],
	)
	if err != nil {
		return nil, err
	}

	const authDataMax = 64
	const cdjMax = 192
	if len(in.WebauthnAuthData) == 0 || len(in.WebauthnAuthData) > authDataMax {
		return nil, fmt.Errorf("WebauthnAuthData length %d not in (0,%d]", len(in.WebauthnAuthData), authDataMax)
	}
	if len(in.WebauthnClientDataJSON) == 0 || len(in.WebauthnClientDataJSON) > cdjMax {
		return nil, fmt.Errorf("WebauthnClientDataJSON length %d not in (0,%d]", len(in.WebauthnClientDataJSON), cdjMax)
	}

	// Build precompile: passkey signs `auth_data || sha256(cdj)`.
	cdjHash := auth.Hashv(in.WebauthnClientDataJSON)
	signedMessage := make([]byte, len(in.WebauthnAuthData)+32)
	copy(signedMessage, in.WebauthnAuthData)
	copy(signedMessage[len(in.WebauthnAuthData):], cdjHash[:])
	preIx, err := auth.BuildSecp256r1PrecompileInstruction(in.PasskeyPubkey[:], signedMessage, in.WebauthnSignature)
	if err != nil {
		return nil, fmt.Errorf("build webauthn precompile: %w", err)
	}

	// Main ix (disc 5).
	w := &ByteWriter{}
	w.U8(5)
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)
	w.U64(in.TxAmount)
	w.U64(in.ExpectedStepUpNonce)
	w.U8(uint8(len(in.WebauthnAuthData)))
	authPad := make([]byte, authDataMax)
	copy(authPad, in.WebauthnAuthData)
	w.Bytes(authPad)
	w.U16(uint16(len(in.WebauthnClientDataJSON)))
	cdjPad := make([]byte, cdjMax)
	copy(cdjPad, in.WebauthnClientDataJSON)
	w.Bytes(cdjPad)

	// Account order matches the on-chain RequestSignatureStepUp struct.
	mainIx := solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(reg.IkaCoordinator, accReadonly),
		meta(msgApproval, accWritable),
		meta(in.Sponsor, accWritableSigner),
		meta(cpiAuth, accReadonly),
		meta(prog, accReadonly),
		meta(reg.IkaProgramID, accReadonly),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// ────────────────────────────────────────────────────────────────
// session-keys
// ────────────────────────────────────────────────────────────────

// SessionKeysCreateSessionInput — args for session-keys::create_session.
//
// Audit C2 (Opção 4) + H6: PDA seed is
// [b"session_key", dwallet, init_authority_hash, session_index]. Multiple
// sessions per (dwallet, init_authority) are supported via different
// session_index values.
type SessionKeysCreateSessionInput struct {
	InitContext
	SessionIndex   uint32
	OwnerSlot      [auth.MemberSlotLen]byte
	SessionKey     solana.PublicKey
	ExpiresAtSlot  uint64
	MaxAmountPerTx uint64
	MaxUses        uint32
}

func BuildSessionKeysCreate(reg *Registry, in SessionKeysCreateSessionInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateSessionKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := SessionKeyPolicyPDA(prog, in.Dwallet, in.InitAuthorityHash, in.SessionIndex)
	if err != nil {
		return nil, err
	}
	challenge := auth.SessionKeysInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.SessionIndex,
		in.OwnerSlot, in.SessionKey, in.ExpiresAtSlot, in.MaxAmountPerTx, in.MaxUses)
	preIx, err := auth.BuildCredentialPrecompile(in.InitAuthoritySlot, challenge,
		in.InitSig.Signature, in.InitSig.WebauthnAuthData, in.InitSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build init precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(0) // disc: create_session
	w.Bytes(in.InitAuthoritySlot[:])
	w.Bytes32(in.InitAuthorityHash)
	w.U32(in.SessionIndex)
	w.Bytes(in.OwnerSlot[:])
	w.Bytes32(in.SessionKey)
	w.U64(in.ExpiresAtSlot)
	w.U64(in.MaxAmountPerTx)
	w.U32(in.MaxUses)
	// Account order matches CreateSession: dwallet, policy, instructions_sysvar,
	// clock, payer, rent, system_program.
	mainIx := solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(in.Sponsor, accWritableSigner),
		meta(sysvarRentAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type SessionKeysAdminAction uint8

const (
	SessionKeysRevoke               SessionKeysAdminAction = 2
	SessionKeysAddAllowedProgram    SessionKeysAdminAction = 3
	SessionKeysRemoveAllowedProgram SessionKeysAdminAction = 4
)

type SessionKeysAdminInput struct {
	AdminContext
	SessionIndex  uint32
	Action        SessionKeysAdminAction
	ProgramID     solana.PublicKey // for add/remove
	ExpectedNonce uint64
	OwnerSig      AdminSignature
}

func BuildSessionKeysAdmin(reg *Registry, in SessionKeysAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateSessionKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := SessionKeyPolicyPDA(prog, in.Dwallet, in.InitAuthorityHash, in.SessionIndex)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	w.U32(in.SessionIndex)
	switch in.Action {
	case SessionKeysRevoke:
		challenge = auth.SessionKeysRevokeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case SessionKeysAddAllowedProgram:
		challenge = auth.SessionKeysAddAllowedProgramChallenge(in.Dwallet, policyPda, in.ProgramID, in.ExpectedNonce, in.OwnerSlot)
		var pid [32]byte
		copy(pid[:], in.ProgramID.Bytes())
		w.Bytes32(pid)
		w.U64(in.ExpectedNonce)
	case SessionKeysRemoveAllowedProgram:
		challenge = auth.SessionKeysRemoveAllowedProgramChallenge(in.Dwallet, policyPda, in.ProgramID, in.ExpectedNonce, in.OwnerSlot)
		var pid [32]byte
		copy(pid[:], in.ProgramID.Bytes())
		w.Bytes32(pid)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid SessionKeysAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// SessionKeysCloseInput — close_session (disc 5). Recipient is bound into
// the close_session_challenge so a stolen signature cannot redirect the
// rent.
type SessionKeysCloseInput struct {
	AdminContext
	SessionIndex  uint32
	Recipient     solana.PublicKey
	ExpectedNonce uint64
	OwnerSig      AdminSignature
}

func BuildSessionKeysClose(reg *Registry, in SessionKeysCloseInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateSessionKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := SessionKeyPolicyPDA(prog, in.Dwallet, in.InitAuthorityHash, in.SessionIndex)
	if err != nil {
		return nil, err
	}
	challenge := auth.SessionKeysCloseSessionChallenge(in.Dwallet, policyPda, in.Recipient, in.ExpectedNonce, in.OwnerSlot)
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(5) // disc: close_session
	w.Bytes32(in.InitAuthorityHash)
	w.U32(in.SessionIndex)
	w.U64(in.ExpectedNonce)
	// Account order matches CloseSession: dwallet, policy, instructions_sysvar,
	// clock, payer, recipient.
	mainIx := solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(in.Sponsor, accWritableSigner),
		meta(in.Recipient, accWritable),
	}, w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// SessionKeysCloseExpiredInput — close_expired_session (disc 6),
// permissionless cleanup. Anyone can submit; the on-chain
// `current_slot >= expires_at_slot` check (now from Clock sysvar) is the
// only gate.
type SessionKeysCloseExpiredInput struct {
	Dwallet           solana.PublicKey
	InitAuthorityHash [32]byte
	SessionIndex      uint32
	Sponsor           solana.PublicKey
	Recipient         solana.PublicKey
}

func BuildSessionKeysCloseExpired(reg *Registry, in SessionKeysCloseExpiredInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateSessionKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := SessionKeyPolicyPDA(prog, in.Dwallet, in.InitAuthorityHash, in.SessionIndex)
	if err != nil {
		return nil, err
	}
	w := &ByteWriter{}
	w.U8(6)
	w.Bytes32(in.InitAuthorityHash)
	w.U32(in.SessionIndex)
	// Account order matches CloseExpiredSession: dwallet, policy, recipient,
	// clock, payer.
	return solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(in.Recipient, accWritable),
		meta(sysvarClockAddress, accReadonly),
		meta(in.Sponsor, accWritableSigner),
	}, w.Result()), nil
}

// SessionKeysRequestSignatureInput — request_signature_via_session (disc 1).
// The session keypair (NOT the user wallet) signs the outer tx alongside
// the gas sponsor.
//
// Audit C2 (Opção 4) + H6: requires init_authority_hash + session_index.
// Audit H3: requires expected_signature_nonce — each request consumes a
// monotonic on-chain nonce so a leaked session_key can produce at most
// one signature per nonce slot.
type SessionKeysRequestSignatureInput struct {
	RequestSigCommon
	SessionIndex           uint32
	SessionSigner          solana.PublicKey
	MessageApprovalBump    uint8
	CpiAuthorityBump       uint8
	Amount                 uint64
	DestinationProgram     [32]byte
	ExpectedSignatureNonce uint64
}

func BuildSessionKeysRequestSignature(reg *Registry, in SessionKeysRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateSessionKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := SessionKeyPolicyPDA(prog, in.Dwallet, in.InitAuthorityHash, in.SessionIndex)
	if err != nil {
		return nil, err
	}
	cpiAuth, _, err := CPIAuthorityPDA(prog)
	if err != nil {
		return nil, err
	}
	msgApproval, _, err := MessageApprovalPDA(
		reg.IkaProgramID,
		in.DwalletCurve, in.DwalletPublicKey,
		in.SignatureScheme,
		in.MessageDigest[:], in.MetaDigest[:],
	)
	if err != nil {
		return nil, err
	}
	w := &ByteWriter{}
	w.U8(1)
	w.Bytes32(in.InitAuthorityHash)
	w.U32(in.SessionIndex)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)
	w.U64(in.Amount)
	w.Bytes32(in.DestinationProgram)
	w.U64(in.ExpectedSignatureNonce)
	return solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(in.SessionSigner, accSigner),
		meta(reg.IkaCoordinator, accReadonly),
		meta(msgApproval, accWritable),
		meta(in.Sponsor, accWritableSigner),
		meta(cpiAuth, accReadonly),
		meta(prog, accReadonly),
		meta(reg.IkaProgramID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, w.Result()), nil
}

// ────────────────────────────────────────────────────────────────
// fhe-gated
// ────────────────────────────────────────────────────────────────

type FHEGatedInitInput struct {
	InitContext
	OwnerSlot           [auth.MemberSlotLen]byte
	FHEAuthority        solana.PublicKey
	DecisionMaxAgeSlots uint64
}

func BuildFHEGatedInit(reg *Registry, in FHEGatedInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateFHEGated)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateFHEGated, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.FHEGatedInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot,
		in.FHEAuthority, in.DecisionMaxAgeSlots)
	preIx, err := auth.BuildCredentialPrecompile(in.InitAuthoritySlot, challenge,
		in.InitSig.Signature, in.InitSig.WebauthnAuthData, in.InitSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build init precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(0)
	w.Bytes(in.InitAuthoritySlot[:])
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes(in.OwnerSlot[:])
	w.Bytes32(in.FHEAuthority)
	w.U64(in.DecisionMaxAgeSlots)
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type FHEGatedAdminAction uint8

const (
	FHEGatedRotateAuthority FHEGatedAdminAction = 2
	FHEGatedPauseAction     FHEGatedAdminAction = 3
	FHEGatedResumeAction    FHEGatedAdminAction = 4
)

type FHEGatedAdminInput struct {
	AdminContext
	Action          FHEGatedAdminAction
	NewFHEAuthority solana.PublicKey
	ExpectedNonce   uint64
	OwnerSig        AdminSignature
}

func BuildFHEGatedAdmin(reg *Registry, in FHEGatedAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateFHEGated)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateFHEGated, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case FHEGatedRotateAuthority:
		challenge = auth.FHEGatedRotateAuthorityChallenge(in.Dwallet, policyPda, in.NewFHEAuthority, in.ExpectedNonce, in.OwnerSlot)
		w.Bytes32(in.NewFHEAuthority)
		w.U64(in.ExpectedNonce)
	case FHEGatedPauseAction:
		challenge = auth.FHEGatedPauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case FHEGatedResumeAction:
		challenge = auth.FHEGatedResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid FHEGatedAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// FHEGatedRequestSignatureInput — request_signature (disc 1). The decision
// is verified end-to-end on-chain via an Ed25519 precompile invocation that
// proves `(fhe_authority, decision_canonical_bytes, decision_signature)`.
// The decision signature comes from Vault Transit `andromeda-fhe`.
type FHEGatedRequestSignatureInput struct {
	RequestSigCommon
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
	DecisionCreatedSlot uint64
	DecisionAuthorize   uint8
	DecisionSignature   []byte // 64 bytes Ed25519 (r||s)
	FHEAuthority        solana.PublicKey
}

func BuildFHEGatedRequestSignature(reg *Registry, in FHEGatedRequestSignatureInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateFHEGated)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateFHEGated, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	cpiAuth, _, err := CPIAuthorityPDA(prog)
	if err != nil {
		return nil, err
	}
	msgApproval, _, err := MessageApprovalPDA(
		reg.IkaProgramID,
		in.DwalletCurve, in.DwalletPublicKey,
		in.SignatureScheme,
		in.MessageDigest[:], in.MetaDigest[:],
	)
	if err != nil {
		return nil, err
	}

	canonical := auth.FHEGatedDecisionCanonicalBytes(policyPda, in.MessageDigest, in.DecisionCreatedSlot, in.DecisionAuthorize)
	preIx, err := auth.BuildEd25519PrecompileInstruction(in.FHEAuthority.Bytes(), canonical[:], in.DecisionSignature)
	if err != nil {
		return nil, fmt.Errorf("build decision precompile: %w", err)
	}

	w := &ByteWriter{}
	w.U8(1)
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)
	w.U64(in.DecisionCreatedSlot)
	w.U8(in.DecisionAuthorize)
	mainIx := solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(in.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(reg.IkaCoordinator, accReadonly),
		meta(msgApproval, accWritable),
		meta(in.Sponsor, accWritableSigner),
		meta(cpiAuth, accReadonly),
		meta(prog, accReadonly),
		meta(reg.IkaProgramID, accReadonly),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}
