// Package policies — instruction builders for the Quasar policy templates v2
// (challenge-based + gas-sponsored).
//
// Every admin / write flow follows the same shape:
//
//  1. Gateway computes the canonical challenge bytes off-chain (see
//     `gateway/internal/auth`) and returns them to the caller.
//  2. The caller's wallet (any chain) signs the challenge off-chain.
//  3. Gateway calls one of the `Build*Admin*` functions below to assemble
//     `[precompilePrecallIx, mainAdminIx]` — the precompile validates the
//     off-chain signature on-chain via `andromeda_auth`; the main ix advances
//     the policy nonce and applies the state mutation.
//  4. The gateway gas-sponsor signer pays + sends the transaction.
//
// `init_policy` is gas-sponsored but challenge-free in most templates (the
// dWallet `transfer_ownership` is what truly arms the policy after init).
// `session-keys::create_session` is the exception — it carries an owner
// challenge with `nonce=0` because creating a session grants signing rights.
//
// `request_signature` is the runtime path called by the dev's app for every
// signed operation; the gas sponsor is the only required signer (except for
// session-keys, where a session keypair co-signs, and passkey-step-up, where
// step-up requires a WebAuthn precompile call alongside).
package policies

import (
	"fmt"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
)

// ── Account-meta helpers ────────────────────────────────────────

type accountRole int

const (
	accReadonly accountRole = iota
	accWritable
	accSigner
	accWritableSigner
)

func meta(addr solana.PublicKey, role accountRole) *solana.AccountMeta {
	switch role {
	case accReadonly:
		return solana.NewAccountMeta(addr, false, false)
	case accWritable:
		return solana.NewAccountMeta(addr, true, false)
	case accSigner:
		return solana.NewAccountMeta(addr, false, true)
	case accWritableSigner:
		return solana.NewAccountMeta(addr, true, true)
	}
	return solana.NewAccountMeta(addr, false, false)
}

var sysvarRentAddress = solana.MustPublicKeyFromBase58("SysvarRent111111111111111111111111111111111")

// Audit C1: gateway must include the Clock sysvar in account slices for
// every program that reads `Sysvar<Clock>` on-chain (which is now every
// instruction that previously took user-supplied `current_ts`/`current_slot`).
var sysvarClockAddress = solana.MustPublicKeyFromBase58("SysvarC1ock11111111111111111111111111111111")

const allowlistMaxDestinations = 32

var _ = allowlistMaxDestinations

// ── Common shapes ───────────────────────────────────────────────

// InitContext carries the credentials that authorize an init_policy call
// under the audit C2 / Opção 4 design.
//
// `InitAuthoritySlot` is the canonical 34-byte member slot of the wallet
// that signs the init challenge. `InitAuthorityHash = sha256(slot)` is
// what participates in the policy PDA seed; the gateway computes it once
// via `InitAuthorityHashFromSlot` and the on-chain handler verifies the
// pair matches before accepting the init.
//
// `Sponsor` is the gas sponsor public key (writable signer of the outer tx).
type InitContext struct {
	Dwallet           solana.PublicKey
	InitAuthoritySlot [MemberSlotLen]byte
	InitAuthorityHash [32]byte
	InitSig           AdminSignature
	Sponsor           solana.PublicKey
}

// AdminContext is the shared context for every non-init admin call.
//
// Audit C2 (Opção 4): `InitAuthorityHash` is required to derive the policy
// PDA — the gateway looks it up from its own database keyed by policy
// address. `OwnerSlot` is the credential that authorizes the admin action.
type AdminContext struct {
	Dwallet           solana.PublicKey
	OwnerSlot         [auth.MemberSlotLen]byte
	InitAuthorityHash [32]byte
	Sponsor           solana.PublicKey
}

// AdminSignature is the `(off-chain signature, optional WebAuthn payload)`
// pair the user produces for a challenge.
type AdminSignature struct {
	Signature              []byte
	WebauthnAuthData       []byte // optional
	WebauthnClientDataJSON []byte // optional
}

// RequestSigCommon bundles the params every template's request_signature
// needs. Sponsor is the gas sponsor (always writable signer of the outer tx).
//
// Audit C2 (Opção 4): `InitAuthorityHash` is required to derive the policy
// PDA. Audit C1: `current_ts` and `current_slot` are NOT in this struct —
// the on-chain handler reads them from the Clock sysvar.
type RequestSigCommon struct {
	Dwallet           solana.PublicKey
	DwalletCurve      uint16
	DwalletPublicKey  []byte
	Sponsor           solana.PublicKey
	InitAuthorityHash [32]byte
	MessageDigest     [32]byte
	MetaDigest        [32]byte
	UserPubkey        [32]byte
	SignatureScheme   uint16
}

// adminAccountSlice constructs the standard 5-account `AdminAction` layout
// shared by every owner-style template (allowlist / velocity / time-lock /
// oracle / passkey / fhe-gated):
//
//  0. dwallet_account     (readonly)
//  1. policy              (writable, mut)
//  2. instructions_sysvar (readonly)
//  3. clock               (readonly)  ← Audit C1
//  4. payer               (writable signer)
func adminAccountSlice(dwallet, policy, sponsor solana.PublicKey) solana.AccountMetaSlice {
	return solana.AccountMetaSlice{
		meta(dwallet, accReadonly),
		meta(policy, accWritable),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(sponsor, accWritableSigner),
	}
}

// initAccountSlice constructs the standard 7-account `InitPolicy` layout
// shared by every owner-style template after Audit C2 (Opção 4):
//
//  0. dwallet_account     (readonly)
//  1. policy              (writable, init)
//  2. payer               (writable signer)
//  3. instructions_sysvar (readonly)
//  4. clock               (readonly)
//  5. rent                (readonly)
//  6. system_program      (readonly)
func initAccountSlice(dwallet, policy, sponsor solana.PublicKey) solana.AccountMetaSlice {
	return solana.AccountMetaSlice{
		meta(dwallet, accReadonly),
		meta(policy, accWritable),
		meta(sponsor, accWritableSigner),
		meta(auth.InstructionsSysvarID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(sysvarRentAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}
}

// ── allowlist-destinations ─────────────────────────────────────

// AllowlistInitInput — args for allowlist-destinations::init_policy.
//
// Audit C2 (Opção 4): caller supplies `InitContext` with init_authority_slot
// + signature, plus the long-lived `OwnerSlot` separately. The on-chain
// handler verifies the precompile signature and binds OwnerSlot into the
// init challenge so it can't be tampered.
type AllowlistInitInput struct {
	InitContext
	OwnerSlot [auth.MemberSlotLen]byte
}

// BuildAllowlistInit returns `[initPrecompileIx, mainInitIx]`.
func BuildAllowlistInit(reg *Registry, in AllowlistInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateAllowlist, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.AllowlistInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot)
	preIx, err := auth.BuildCredentialPrecompile(in.InitAuthoritySlot, challenge,
		in.InitSig.Signature, in.InitSig.WebauthnAuthData, in.InitSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build init precompile: %w", err)
	}
	w := &ByteWriter{}
	w.U8(0) // disc: init_policy
	w.Bytes(in.InitAuthoritySlot[:])
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes(in.OwnerSlot[:])
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// AllowlistAdminAction enumerates the four owner admin operations on the
// allowlist-destinations template.
type AllowlistAdminAction uint8

const (
	AllowlistAddDestination    AllowlistAdminAction = 2
	AllowlistPauseAction       AllowlistAdminAction = 3
	AllowlistResumeAction      AllowlistAdminAction = 4
	AllowlistRemoveDestination AllowlistAdminAction = 5
)

// AllowlistAdminInput — single input shape for all 4 owner admin actions.
type AllowlistAdminInput struct {
	AdminContext
	Action        AllowlistAdminAction
	Destination   [32]byte // required for add/remove
	ExpectedNonce uint64
	OwnerSig      AdminSignature
}

// BuildAllowlistAdmin returns `[precompileIx, mainIx]` so the gateway can
// signAndSend in one shot.
//
// Audit C2 (Opção 4): wire format prefixed with init_authority_hash so
// Quasar derives the policy PDA correctly.
// Audit C1: current_ts no longer in wire — on-chain reads from Clock sysvar.
func BuildAllowlistAdmin(reg *Registry, in AllowlistAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateAllowlist, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}

	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action)) // disc
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case AllowlistAddDestination:
		challenge = auth.AllowlistAddDestinationChallenge(in.Dwallet, policyPda, in.Destination, in.ExpectedNonce, in.OwnerSlot)
		w.Bytes32(in.Destination)
		w.U64(in.ExpectedNonce)
	case AllowlistRemoveDestination:
		challenge = auth.AllowlistRemoveDestinationChallenge(in.Dwallet, policyPda, in.Destination, in.ExpectedNonce, in.OwnerSlot)
		w.Bytes32(in.Destination)
		w.U64(in.ExpectedNonce)
	case AllowlistPauseAction:
		challenge = auth.AllowlistPauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case AllowlistResumeAction:
		challenge = auth.AllowlistResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid AllowlistAdminAction %d", in.Action)
	}

	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

// AllowlistRequestSignatureInput — args for allowlist-destinations::request_signature.
type AllowlistRequestSignatureInput struct {
	RequestSigCommon
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
	Destination         [32]byte
}

func BuildAllowlistRequestSignature(reg *Registry, in AllowlistRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	w := &ByteWriter{}
	w.U8(1) // disc: request_signature
	w.Bytes32(in.InitAuthorityHash)
	w.Bytes32(in.MessageDigest)
	w.Bytes32(in.MetaDigest)
	w.Bytes32(in.UserPubkey)
	w.U16(in.SignatureScheme)
	w.U8(in.MessageApprovalBump)
	w.U8(in.CpiAuthorityBump)
	w.Bytes32(in.Destination)
	return buildRequestSig(prog, reg, TemplateAllowlist, in.RequestSigCommon, w.Result())
}

// ── velocity-guard ─────────────────────────────────────────────

type VelocityInitInput struct {
	InitContext
	OwnerSlot        [auth.MemberSlotLen]byte
	MaxSigsPerWindow uint32
	WindowSlots      uint64
}

func BuildVelocityInit(reg *Registry, in VelocityInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateVelocityGuard)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateVelocityGuard, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.VelocityInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot, in.MaxSigsPerWindow, in.WindowSlots)
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
	w.U32(in.MaxSigsPerWindow)
	w.U64(in.WindowSlots)
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type VelocityAdminAction uint8

const (
	VelocityUpdateWindow VelocityAdminAction = 2
	VelocityPauseAction  VelocityAdminAction = 3
	VelocityResumeAction VelocityAdminAction = 4
)

type VelocityAdminInput struct {
	AdminContext
	Action           VelocityAdminAction
	MaxSigsPerWindow uint32 // for update-window
	WindowSlots      uint64 // for update-window
	ExpectedNonce    uint64
	OwnerSig         AdminSignature
}

func BuildVelocityAdmin(reg *Registry, in VelocityAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateVelocityGuard)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateVelocityGuard, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case VelocityUpdateWindow:
		challenge = auth.VelocityUpdateWindowChallenge(in.Dwallet, policyPda, in.MaxSigsPerWindow, in.WindowSlots, in.ExpectedNonce, in.OwnerSlot)
		w.U32(in.MaxSigsPerWindow)
		w.U64(in.WindowSlots)
		w.U64(in.ExpectedNonce)
	case VelocityPauseAction:
		challenge = auth.VelocityPauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case VelocityResumeAction:
		challenge = auth.VelocityResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid VelocityAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type VelocityRequestSignatureInput struct {
	RequestSigCommon
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
}

func BuildVelocityRequestSignature(reg *Registry, in VelocityRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateVelocityGuard)
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
	return buildRequestSig(prog, reg, TemplateVelocityGuard, in.RequestSigCommon, w.Result())
}

// ── time-lock ──────────────────────────────────────────────────

type TimeLockInitInput struct {
	InitContext
	OwnerSlot            [auth.MemberSlotLen]byte
	Mode                 uint8
	StartSlot            uint64
	EndSlot              uint64
	RecurringPeriodSlots uint64
}

func BuildTimeLockInit(reg *Registry, in TimeLockInitInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateTimeLock)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateTimeLock, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	challenge := auth.TimeLockInitPolicyChallenge(in.Dwallet, in.InitAuthoritySlot, in.OwnerSlot,
		in.Mode, in.StartSlot, in.EndSlot, in.RecurringPeriodSlots)
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
	w.U8(in.Mode)
	w.U64(in.StartSlot)
	w.U64(in.EndSlot)
	w.U64(in.RecurringPeriodSlots)
	mainIx := solana.NewInstruction(prog, initAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type TimeLockAdminAction uint8

const (
	TimeLockUpdateWindow TimeLockAdminAction = 2
	TimeLockPauseAction  TimeLockAdminAction = 3
	TimeLockResumeAction TimeLockAdminAction = 4
)

type TimeLockAdminInput struct {
	AdminContext
	Action               TimeLockAdminAction
	Mode                 uint8
	StartSlot            uint64
	EndSlot              uint64
	RecurringPeriodSlots uint64
	ExpectedNonce        uint64
	OwnerSig             AdminSignature
}

func BuildTimeLockAdmin(reg *Registry, in TimeLockAdminInput) ([]solana.Instruction, error) {
	prog, err := reg.ProgramID(TemplateTimeLock)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotDeployed, err)
	}
	policyPda, _, err := PolicyPDA(TemplateTimeLock, prog, in.Dwallet, in.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	var challenge [32]byte
	w := &ByteWriter{}
	w.U8(uint8(in.Action))
	w.Bytes32(in.InitAuthorityHash)
	switch in.Action {
	case TimeLockUpdateWindow:
		challenge = auth.TimeLockUpdateWindowChallenge(in.Dwallet, policyPda, in.Mode, in.StartSlot, in.EndSlot, in.RecurringPeriodSlots, in.ExpectedNonce, in.OwnerSlot)
		w.U8(in.Mode)
		w.U64(in.StartSlot)
		w.U64(in.EndSlot)
		w.U64(in.RecurringPeriodSlots)
		w.U64(in.ExpectedNonce)
	case TimeLockPauseAction:
		challenge = auth.TimeLockPauseChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	case TimeLockResumeAction:
		challenge = auth.TimeLockResumeChallenge(in.Dwallet, policyPda, in.ExpectedNonce, in.OwnerSlot)
		w.U64(in.ExpectedNonce)
	default:
		return nil, fmt.Errorf("invalid TimeLockAdminAction %d", in.Action)
	}
	preIx, err := auth.BuildCredentialPrecompile(in.OwnerSlot, challenge, in.OwnerSig.Signature, in.OwnerSig.WebauthnAuthData, in.OwnerSig.WebauthnClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("build owner precompile: %w", err)
	}
	mainIx := solana.NewInstruction(prog, adminAccountSlice(in.Dwallet, policyPda, in.Sponsor), w.Result())
	return []solana.Instruction{preIx, mainIx}, nil
}

type TimeLockRequestSignatureInput struct {
	RequestSigCommon
	MessageApprovalBump uint8
	CpiAuthorityBump    uint8
}

func BuildTimeLockRequestSignature(reg *Registry, in TimeLockRequestSignatureInput) (*solana.GenericInstruction, error) {
	prog, err := reg.ProgramID(TemplateTimeLock)
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
	return buildRequestSig(prog, reg, TemplateTimeLock, in.RequestSigCommon, w.Result())
}

// ── Shared request_signature account layout ────────────────────
//
// Audit C2 (Opção 4): policy PDA derived from
// (dwallet, init_authority_hash) — caller passes hash via `c.InitAuthorityHash`.
// Audit C1: account slice now includes the Clock sysvar between dwallet_program
// and system_program.
//
// Used by templates whose `RequestSignature` Accounts struct matches the
// canonical 10-account layout. oracle-conditional / passkey-step-up /
// session-keys / fhe-gated have extra accounts and build their own slices
// (see `instructions_extras.go`).
func buildRequestSig(
	prog solana.PublicKey,
	reg *Registry,
	template string,
	c RequestSigCommon,
	data []byte,
) (*solana.GenericInstruction, error) {
	policyPda, _, err := PolicyPDA(template, prog, c.Dwallet, c.InitAuthorityHash)
	if err != nil {
		return nil, err
	}
	cpiAuth, _, err := CPIAuthorityPDA(prog)
	if err != nil {
		return nil, err
	}
	msgApproval, _, err := MessageApprovalPDA(
		reg.IkaProgramID,
		c.DwalletCurve, c.DwalletPublicKey,
		c.SignatureScheme,
		c.MessageDigest[:], c.MetaDigest[:],
	)
	if err != nil {
		return nil, err
	}
	return solana.NewInstruction(prog, solana.AccountMetaSlice{
		meta(c.Dwallet, accReadonly),
		meta(policyPda, accWritable),
		meta(reg.IkaCoordinator, accReadonly),
		meta(msgApproval, accWritable),
		meta(c.Sponsor, accWritableSigner),
		meta(cpiAuth, accReadonly),
		meta(prog, accReadonly),
		meta(reg.IkaProgramID, accReadonly),
		meta(sysvarClockAddress, accReadonly),
		meta(solana.SystemProgramID, accReadonly),
	}, data), nil
}
