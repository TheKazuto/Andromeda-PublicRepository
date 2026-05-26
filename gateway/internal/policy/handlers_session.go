// Update 8 (2026-05-26) — Session lifecycle handlers.
//
// Andromeda exposes the on-chain session primitives (disc 100-106) as REST so a
// dev can build their own delegation layer on top: open a bounded session (the
// dWallet owner signs once), use it from a session-signer keypair under the
// limits, revoke/close when done. We deliberately do NOT orchestrate the dev's
// loop here — no per-session storage, no agent runtime, no scheduler. The
// gateway provides the challenge/submit primitives and a build-only endpoint
// for `disc 101` (use); the dev composes the lifecycle in their own infra.
//
// Security model: every admin op (open/revoke/close/add_dest/remove_dest)
// requires the dWallet owner's off-chain signature on a canonical
// `admin_challenge` recomputed on-chain. The session-signer is generated
// client-side and NEVER touches the gateway — Andromeda relays it as
// `IsSigner: true` on disc 101 but never custodies it.
package policy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// ── Shared DTOs ──────────────────────────────────────────────────────────────

// sessionOpenChallengeRequest carries the inputs the gateway needs to derive
// the `session_open` (disc 100) challenge. The owner signs the returned
// `owner_auth_challenge_hex` off-chain and submits the signature back via
// /v1/policy/session/open/submit.
type sessionOpenChallengeRequest struct {
	DwalletAddress      string          `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash   string          `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	RuleIndex           uint8           `json:"rule_index" validate:"max=15"`
	RuleGeneration      uint32          `json:"rule_generation"`
	RuleConfigHashHex   string          `json:"rule_config_hash_hex" validate:"required,hex_len=32"`
	ExpectedNonce       uint64          `json:"expected_nonce"`
	OwnerSlot           *memberSlotJSON `json:"owner_slot" validate:"required"`
	SessionIndex        uint32          `json:"session_index" validate:"max=255"`
	SessionSignerPubkey string          `json:"session_signer_pubkey" validate:"required,solana_pubkey"`
	ExpiresAtTs         int64           `json:"expires_at_ts" validate:"required"`
	MaxUses             uint32          `json:"max_uses" validate:"required,min=1"`
	MaxAmountPerTx      uint64          `json:"max_amount_per_tx" validate:"required,min=1"`
}

// sessionAdminChallengeResponse is the canonical envelope every session
// challenge endpoint returns. The dev shows `human_message` to the owner,
// collects the signature on `owner_auth_challenge_hex`, then calls the
// matching /submit with the same inputs + the signature.
type sessionAdminChallengeResponse struct {
	EngineAddress         string `json:"engine_address"`
	SessionAddress        string `json:"session_address"`
	OpTag                 string `json:"op_tag"`
	HumanMessage          string `json:"human_message"`
	OwnerAuthChallengeHex string `json:"owner_auth_challenge_hex"`
	OwnerAuthPreimageHex  string `json:"owner_auth_preimage_hex"`
	ExpectedNonce         uint64 `json:"expected_nonce"`
}

// sessionAdminSubmitRequest is the canonical envelope every admin /submit
// accepts. Specific ops (close / add_dest / remove_dest) embed it and add
// their own typed fields (recipient, destination).
type sessionAdminSubmitRequest struct {
	DwalletAddress         string          `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash      string          `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	RuleIndex              uint8           `json:"rule_index" validate:"max=15"`
	RuleGeneration         uint32          `json:"rule_generation"`
	RuleConfigHashHex      string          `json:"rule_config_hash_hex" validate:"required,hex_len=32"`
	ExpectedNonce          uint64          `json:"expected_nonce"`
	OwnerSlot              *memberSlotJSON `json:"owner_slot" validate:"required"`
	SignatureBase64        string          `json:"signature_base64" validate:"required,base64"`
	WebauthnAuthDataBase64 string          `json:"webauthn_auth_data_base64,omitempty" validate:"omitempty,base64"`
	WebauthnCDJBase64      string          `json:"webauthn_cdj_base64,omitempty" validate:"omitempty,base64"`
	SessionIndex           uint32          `json:"session_index" validate:"max=255"`
}

// sessionDerived consolidates the PDAs every session admin op derives.
type sessionDerived struct {
	dwallet    solana.PublicKey
	initHash   [32]byte
	engine     solana.PublicKey
	rulePDA    solana.PublicKey
	sessionPDA solana.PublicKey
	configHash [32]byte
	ownerSlot  [MemberSlotLen]byte
}

func (s *Service) deriveSessionAdmin(
	dwalletAddr, initAuthHash, configHash string,
	ruleIndex uint8, sessionIndex uint32, ownerSlotJSON *memberSlotJSON,
) (*sessionDerived, *buildError) {
	dwallet, err := solana.PublicKeyFromBase58(dwalletAddr)
	if err != nil {
		return nil, &buildError{http.StatusBadRequest, "invalid_field", "dwallet_address: " + err.Error()}
	}
	initHash, err := mustHex32(initAuthHash)
	if err != nil {
		return nil, &buildError{http.StatusBadRequest, "invalid_field", "init_authority_hash_hex: " + err.Error()}
	}
	cfgHash, err := mustHex32(configHash)
	if err != nil {
		return nil, &buildError{http.StatusBadRequest, "invalid_field", "rule_config_hash_hex: " + err.Error()}
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindSessionKey, ruleIndex)
	if err != nil {
		return nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	sessionPDA, _, err := SessionPDA(s.ProgramID, engine, sessionIndex)
	if err != nil {
		return nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	if ownerSlotJSON == nil {
		return nil, &buildError{http.StatusBadRequest, "invalid_field", "owner_slot is required"}
	}
	ownerSlot, err := ownerSlotJSON.decode()
	if err != nil {
		return nil, &buildError{http.StatusBadRequest, "invalid_field", "owner_slot: " + err.Error()}
	}
	return &sessionDerived{
		dwallet:    dwallet,
		initHash:   initHash,
		engine:     engine,
		rulePDA:    rulePDA,
		sessionPDA: sessionPDA,
		configHash: cfgHash,
		ownerSlot:  ownerSlot,
	}, nil
}

// buildSessionAdminChallenge constructs the canonical AdminChallengeInput for
// a session admin op. `engineLevel == true` selects the engine-level admin
// path (only `session_open` uses this — the rule_index/generation/config_hash
// are real and the nonce is the engine's). `engineLevel == false` selects the
// per-session admin path (revoke/close/add/remove): rule_index=0, generation=0,
// config_hash=zero, nonce is the session's `next_admin_nonce`.
func buildSessionAdminChallenge(
	opTag []byte,
	engine, dwallet solana.PublicKey,
	ownerSlot [MemberSlotLen]byte,
	expectedNonce uint64,
	engineLevel bool,
	configHash [32]byte,
	ruleIndex uint8,
	ruleGeneration uint32,
	extras [][]byte,
) (*AdminChallengeInput, []byte, [32]byte, error) {
	// Human message — matches the on-chain handler placeholder
	// (`allowlist_pause_message` is reused for every session admin op until a
	// dedicated session human renderer ships). The on-chain side calls the same
	// helper, so the hash matches byte-for-byte.
	human := HumanMessageAllowlistPause(engine, dwallet)
	var rk uint8 = uint8(KindSessionKey)
	var rg uint32 = ruleGeneration
	var rIdx uint8 = ruleIndex
	var cfg [32]byte = configHash
	if !engineLevel {
		// Per-session admin path: rule_index=0, generation=0, config_hash=zero —
		// mirror of the on-chain `admin_challenge(..., 0, 0, ..., &[0u8;32], ...)`.
		rIdx = 0
		rg = 0
		cfg = [32]byte{}
	}
	in := &AdminChallengeInput{
		OpTag:          opTag,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       rk,
		RuleIndex:      rIdx,
		RuleGeneration: rg,
		ExpectedNonce:  expectedNonce,
		ConfigHash:     cfg,
		OwnerSlot:      ownerSlot,
		Extras:         extras,
	}
	pre, err := in.Preimage()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	h, err := in.Hash()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	return in, pre, h, nil
}

// decodeOwnerSig parses the owner credential payload shared by every session
// admin /submit. Returns the raw bytes + the WebAuthn extras.
func decodeOwnerSig(req *sessionAdminSubmitRequest) (sig, authData, cdj []byte, err *buildError) {
	s, e := base64Decode(req.SignatureBase64)
	if e != nil {
		return nil, nil, nil, &buildError{http.StatusBadRequest, "invalid_field", "signature_base64: " + e.Error()}
	}
	var ad, c []byte
	if req.WebauthnAuthDataBase64 != "" {
		if ad, e = base64Decode(req.WebauthnAuthDataBase64); e != nil {
			return nil, nil, nil, &buildError{http.StatusBadRequest, "invalid_field", "webauthn_auth_data_base64: " + e.Error()}
		}
	}
	if req.WebauthnCDJBase64 != "" {
		if c, e = base64Decode(req.WebauthnCDJBase64); e != nil {
			return nil, nil, nil, &buildError{http.StatusBadRequest, "invalid_field", "webauthn_cdj_base64: " + e.Error()}
		}
	}
	return s, ad, c, nil
}

// base64Decode wraps stdlib (kept as a thin helper so all session handlers
// share the same decoder).
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ── /v1/policy/session/open/{challenge,submit} ──────────────────────────────

func (s *Service) sessionOpenChallenge(w http.ResponseWriter, r *http.Request) {
	var req sessionOpenChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	d, berr := s.deriveSessionAdmin(req.DwalletAddress, req.InitAuthorityHash, req.RuleConfigHashHex,
		req.RuleIndex, req.SessionIndex, req.OwnerSlot)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	signerPK, err := solana.PublicKeyFromBase58(req.SessionSignerPubkey)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "session_signer_pubkey: "+err.Error())
		return
	}
	extras := sessionOpenExtras(req.SessionIndex, signerPK, req.ExpiresAtTs, req.MaxUses, req.MaxAmountPerTx)
	_, pre, h, err := buildSessionAdminChallenge(
		OpSessionOpen,
		d.engine, d.dwallet, d.ownerSlot,
		req.ExpectedNonce,
		true, // engine-level admin path
		d.configHash, req.RuleIndex, req.RuleGeneration,
		extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionAdminChallengeResponse{
		EngineAddress:         d.engine.String(),
		SessionAddress:        d.sessionPDA.String(),
		OpTag:                 string(OpSessionOpen),
		HumanMessage:          string(HumanMessageAllowlistPause(d.engine, d.dwallet)),
		OwnerAuthChallengeHex: hex.EncodeToString(h[:]),
		OwnerAuthPreimageHex:  hex.EncodeToString(pre),
		ExpectedNonce:         req.ExpectedNonce,
	})
}

// sessionOpenSubmitRequest extends the canonical admin submit envelope with the
// disc-100-specific fields. RuleConfigHashHex is inherited from
// `sessionAdminSubmitRequest` via embedding — DO NOT redeclare it here or the
// `json:"-"` shadow would prevent the JSON decoder from populating it and the
// validator would fail every request with "required".
type sessionOpenSubmitRequest struct {
	sessionAdminSubmitRequest
	SessionSignerPubkey string `json:"session_signer_pubkey" validate:"required,solana_pubkey"`
	ExpiresAtTs         int64  `json:"expires_at_ts" validate:"required"`
	MaxUses             uint32 `json:"max_uses" validate:"required,min=1"`
	MaxAmountPerTx      uint64 `json:"max_amount_per_tx" validate:"required,min=1"`
}

func (s *Service) sessionOpenSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req sessionOpenSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	d, berr := s.deriveSessionAdmin(req.DwalletAddress, req.InitAuthorityHash, req.RuleConfigHashHex,
		req.RuleIndex, req.SessionIndex, req.OwnerSlot)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	signerPK, err := solana.PublicKeyFromBase58(req.SessionSignerPubkey)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "session_signer_pubkey: "+err.Error())
		return
	}
	extras := sessionOpenExtras(req.SessionIndex, signerPK, req.ExpiresAtTs, req.MaxUses, req.MaxAmountPerTx)
	_, _, h, err := buildSessionAdminChallenge(
		OpSessionOpen, d.engine, d.dwallet, d.ownerSlot,
		req.ExpectedNonce, true, d.configHash, req.RuleIndex, req.RuleGeneration, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	sig, authData, cdj, sigErr := decodeOwnerSig(&req.sessionAdminSubmitRequest)
	if sigErr != nil {
		httpx.WriteError(w, sigErr.status, sigErr.code, sigErr.msg)
		return
	}
	precompile, err := buildCredentialPrecompile(d.ownerSlot, h, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := SessionOpen(SessionOpenParams{
		ProgramID:         s.ProgramID,
		Engine:            d.engine,
		DWallet:           d.dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: d.initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         req.RuleIndex,
		SessionIndex:      req.SessionIndex,
		SessionSigner:     signerPK,
		ExpiresAtTs:       req.ExpiresAtTs,
		MaxUses:           req.MaxUses,
		MaxAmountPerTx:    req.MaxAmountPerTx,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	sigOut, err := s.GasSponsor.SignAndSend(r.Context(), []solana.Instruction{precompile, mainIx})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}
	extra := fmt.Sprintf(`{"session_index":%d,"expires_at_ts":%d,"max_uses":%d,"max_amount_per_tx":%d}`,
		req.SessionIndex, req.ExpiresAtTs, req.MaxUses, req.MaxAmountPerTx)
	s.appendAuditSubmit(r, "session.open", d.engine.String(), d.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: d.engine.String(),
	})
}

// sessionOpenExtras packs the disc 100 extras into the same byte slices the
// on-chain `admin_challenge(..., extras)` call uses. Mirror byte-for-byte of
// the `&[&session_idx_le, session_signer_bytes, &expires_le, &uses_le, &amount_le]`
// in lib.rs::session_open.
func sessionOpenExtras(sessionIndex uint32, signer solana.PublicKey, expiresAt int64, maxUses uint32, maxAmount uint64) [][]byte {
	var idx [4]byte
	leU32(idx[:], sessionIndex)
	var exp [8]byte
	leU64(exp[:], uint64(expiresAt))
	var uses [4]byte
	leU32(uses[:], maxUses)
	var amount [8]byte
	leU64(amount[:], maxAmount)
	return [][]byte{idx[:], signer.Bytes(), exp[:], uses[:], amount[:]}
}

// ── /v1/policy/session/{revoke,close,destinations/add,destinations/remove}/{challenge,submit} ─

// sessionAdminInputs is shared by every per-session admin op
// (revoke/close/add/remove). The on-chain handler reads the session's
// next_admin_nonce, not the engine's — so the dev calls the gateway with the
// expected_nonce they observed on-chain (or via the read endpoint).
type sessionAdminInputs struct {
	DwalletAddress    string          `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string          `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	SessionIndex      uint32          `json:"session_index" validate:"max=255"`
	ExpectedNonce     uint64          `json:"expected_nonce"`
	OwnerSlot         *memberSlotJSON `json:"owner_slot" validate:"required"`
}

// zero32HexPlaceholder is the 32-byte all-zero value as 64 hex chars used by
// per-session admin ops as the placeholder config_hash (the on-chain
// `admin_challenge` always passes `&[0u8; 32]` on these paths).
const zero32HexPlaceholder = "0000000000000000000000000000000000000000000000000000000000000000"

func (s *Service) deriveSessionPerSession(in sessionAdminInputs) (*sessionDerived, *buildError) {
	// Per-session ops don't carry the rule config — pass the placeholder so the
	// derive helper still passes its hex32 validation. The on-chain side uses
	// zero anyway. We still need the engine + session PDAs.
	return s.deriveSessionAdmin(in.DwalletAddress, in.InitAuthorityHash, zero32HexPlaceholder, 0, in.SessionIndex, in.OwnerSlot)
}

// ── revoke (disc 102) ────────────────────────────────────────────────────────

type sessionRevokeRequest struct{ sessionAdminInputs }
type sessionRevokeSubmitRequest struct {
	sessionAdminInputs
	SignatureBase64        string `json:"signature_base64" validate:"required,base64"`
	WebauthnAuthDataBase64 string `json:"webauthn_auth_data_base64,omitempty" validate:"omitempty,base64"`
	WebauthnCDJBase64      string `json:"webauthn_cdj_base64,omitempty" validate:"omitempty,base64"`
}

func (s *Service) sessionRevokeChallenge(w http.ResponseWriter, r *http.Request) {
	var req sessionRevokeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	extras := sessionRevokeExtras(d.sessionPDA, req.SessionIndex)
	_, pre, h, err := buildSessionAdminChallenge(
		OpSessionRevoke, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionAdminChallengeResponse{
		EngineAddress:         d.engine.String(),
		SessionAddress:        d.sessionPDA.String(),
		OpTag:                 string(OpSessionRevoke),
		HumanMessage:          string(HumanMessageAllowlistPause(d.engine, d.dwallet)),
		OwnerAuthChallengeHex: hex.EncodeToString(h[:]),
		OwnerAuthPreimageHex:  hex.EncodeToString(pre),
		ExpectedNonce:         req.ExpectedNonce,
	})
}

func (s *Service) sessionRevokeSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req sessionRevokeSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	extras := sessionRevokeExtras(d.sessionPDA, req.SessionIndex)
	_, _, h, err := buildSessionAdminChallenge(
		OpSessionRevoke, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, perr := s.adminPrecompile(w, d.ownerSlot, h, req.SignatureBase64, req.WebauthnAuthDataBase64, req.WebauthnCDJBase64)
	if perr {
		return
	}
	mainIx, err := SessionRevoke(SessionRevokeParams{
		ProgramID:         s.ProgramID,
		Engine:            d.engine,
		DWallet:           d.dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: d.initHash,
		SessionIndex:      req.SessionIndex,
		ExpectedNonce:     req.ExpectedNonce,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	s.sendSessionAdminTx(w, r, d, []solana.Instruction{precompile, mainIx},
		"session.revoke", fmt.Sprintf(`{"session_index":%d}`, req.SessionIndex))
}

// sessionRevokeExtras mirrors the on-chain extras
// `&[session_addr.as_array().as_slice(), &idx_le]` for `session_revoke`
// (lib.rs disc 102). MUST return the FULL extras list — challenge and submit
// recompute the same hash; any mismatch makes the precompile verification fail.
func sessionRevokeExtras(sessionPDA solana.PublicKey, sessionIndex uint32) [][]byte {
	var idx [4]byte
	leU32(idx[:], sessionIndex)
	return [][]byte{sessionPDA.Bytes(), idx[:]}
}

// ── close (disc 103) ─────────────────────────────────────────────────────────

type sessionCloseRequest struct {
	sessionAdminInputs
	Recipient string `json:"recipient" validate:"required,solana_pubkey"`
}
type sessionCloseSubmitRequest struct {
	sessionCloseRequest
	SignatureBase64        string `json:"signature_base64" validate:"required,base64"`
	WebauthnAuthDataBase64 string `json:"webauthn_auth_data_base64,omitempty" validate:"omitempty,base64"`
	WebauthnCDJBase64      string `json:"webauthn_cdj_base64,omitempty" validate:"omitempty,base64"`
}

func (s *Service) sessionCloseChallenge(w http.ResponseWriter, r *http.Request) {
	var req sessionCloseRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	recipient, err := solana.PublicKeyFromBase58(req.Recipient)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "recipient: "+err.Error())
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	extras := sessionCloseExtras(d.sessionPDA, req.SessionIndex, recipient)
	_, pre, h, err := buildSessionAdminChallenge(
		OpSessionClose, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionAdminChallengeResponse{
		EngineAddress:         d.engine.String(),
		SessionAddress:        d.sessionPDA.String(),
		OpTag:                 string(OpSessionClose),
		HumanMessage:          string(HumanMessageAllowlistPause(d.engine, d.dwallet)),
		OwnerAuthChallengeHex: hex.EncodeToString(h[:]),
		OwnerAuthPreimageHex:  hex.EncodeToString(pre),
		ExpectedNonce:         req.ExpectedNonce,
	})
}

func (s *Service) sessionCloseSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req sessionCloseSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	recipient, err := solana.PublicKeyFromBase58(req.Recipient)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "recipient: "+err.Error())
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	extras := sessionCloseExtras(d.sessionPDA, req.SessionIndex, recipient)
	_, _, h, err := buildSessionAdminChallenge(
		OpSessionClose, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, perr := s.adminPrecompile(w, d.ownerSlot, h, req.SignatureBase64, req.WebauthnAuthDataBase64, req.WebauthnCDJBase64)
	if perr {
		return
	}
	mainIx, err := SessionClose(SessionCloseParams{
		ProgramID:         s.ProgramID,
		Engine:            d.engine,
		DWallet:           d.dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		Recipient:         recipient,
		InitAuthorityHash: d.initHash,
		SessionIndex:      req.SessionIndex,
		ExpectedNonce:     req.ExpectedNonce,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	s.sendSessionAdminTx(w, r, d, []solana.Instruction{precompile, mainIx},
		"session.close", fmt.Sprintf(`{"session_index":%d,"recipient":"%s"}`, req.SessionIndex, recipient.String()))
}

func sessionCloseExtras(sessionPDA solana.PublicKey, sessionIndex uint32, recipient solana.PublicKey) [][]byte {
	var idx [4]byte
	leU32(idx[:], sessionIndex)
	rec := recipient.Bytes()
	return [][]byte{sessionPDA.Bytes(), idx[:], rec}
}

// ── destinations add (disc 105) / remove (disc 106) ─────────────────────────

type sessionDestRequest struct {
	sessionAdminInputs
	DestinationHex string `json:"destination_hex" validate:"required,hex_len=32"`
}
type sessionDestSubmitRequest struct {
	sessionDestRequest
	SignatureBase64        string `json:"signature_base64" validate:"required,base64"`
	WebauthnAuthDataBase64 string `json:"webauthn_auth_data_base64,omitempty" validate:"omitempty,base64"`
	WebauthnCDJBase64      string `json:"webauthn_cdj_base64,omitempty" validate:"omitempty,base64"`
}

func (s *Service) sessionDestAddChallenge(w http.ResponseWriter, r *http.Request) {
	s.sessionDestChallenge(w, r, OpSessionAddDest)
}

func (s *Service) sessionDestRemoveChallenge(w http.ResponseWriter, r *http.Request) {
	s.sessionDestChallenge(w, r, OpSessionRemoveDest)
}

func (s *Service) sessionDestChallenge(w http.ResponseWriter, r *http.Request, opTag []byte) {
	var req sessionDestRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	dest, err := mustHex32(req.DestinationHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "destination_hex: "+err.Error())
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	extras := sessionDestExtras(d.sessionPDA, req.SessionIndex, dest)
	_, pre, h, err := buildSessionAdminChallenge(
		opTag, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionAdminChallengeResponse{
		EngineAddress:         d.engine.String(),
		SessionAddress:        d.sessionPDA.String(),
		OpTag:                 string(opTag),
		HumanMessage:          string(HumanMessageAllowlistPause(d.engine, d.dwallet)),
		OwnerAuthChallengeHex: hex.EncodeToString(h[:]),
		OwnerAuthPreimageHex:  hex.EncodeToString(pre),
		ExpectedNonce:         req.ExpectedNonce,
	})
}

func (s *Service) sessionDestAddSubmit(w http.ResponseWriter, r *http.Request) {
	s.sessionDestSubmit(w, r, true)
}

func (s *Service) sessionDestRemoveSubmit(w http.ResponseWriter, r *http.Request) {
	s.sessionDestSubmit(w, r, false)
}

func (s *Service) sessionDestSubmit(w http.ResponseWriter, r *http.Request, isAdd bool) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req sessionDestSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	dest, err := mustHex32(req.DestinationHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "destination_hex: "+err.Error())
		return
	}
	d, berr := s.deriveSessionPerSession(req.sessionAdminInputs)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return
	}
	opTag := OpSessionAddDest
	if !isAdd {
		opTag = OpSessionRemoveDest
	}
	extras := sessionDestExtras(d.sessionPDA, req.SessionIndex, dest)
	_, _, h, err := buildSessionAdminChallenge(
		opTag, d.engine, d.dwallet, d.ownerSlot, req.ExpectedNonce, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, perr := s.adminPrecompile(w, d.ownerSlot, h, req.SignatureBase64, req.WebauthnAuthDataBase64, req.WebauthnCDJBase64)
	if perr {
		return
	}
	var mainIx solana.Instruction
	if isAdd {
		mainIx, err = SessionAddDestination(SessionAddDestinationParams{
			ProgramID:         s.ProgramID,
			Engine:            d.engine,
			DWallet:           d.dwallet,
			Payer:             s.GasSponsor.PublicKey(),
			InitAuthorityHash: d.initHash,
			SessionIndex:      req.SessionIndex,
			ExpectedNonce:     req.ExpectedNonce,
			Destination:       dest,
		})
	} else {
		mainIx, err = SessionRemoveDestination(SessionRemoveDestinationParams{
			ProgramID:         s.ProgramID,
			Engine:            d.engine,
			DWallet:           d.dwallet,
			Payer:             s.GasSponsor.PublicKey(),
			InitAuthorityHash: d.initHash,
			SessionIndex:      req.SessionIndex,
			ExpectedNonce:     req.ExpectedNonce,
			Destination:       dest,
		})
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	action := "session.destinations.add"
	if !isAdd {
		action = "session.destinations.remove"
	}
	s.sendSessionAdminTx(w, r, d, []solana.Instruction{precompile, mainIx},
		action, fmt.Sprintf(`{"session_index":%d,"destination":"%s"}`, req.SessionIndex, req.DestinationHex))
}

func sessionDestExtras(sessionPDA solana.PublicKey, sessionIndex uint32, dest [32]byte) [][]byte {
	var idx [4]byte
	leU32(idx[:], sessionIndex)
	return [][]byte{sessionPDA.Bytes(), idx[:], dest[:]}
}

// ── close-expired (disc 104, permissionless) ────────────────────────────────

type sessionCloseExpiredRequest struct {
	DwalletAddress    string `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	SessionIndex      uint32 `json:"session_index" validate:"max=255"`
	Recipient         string `json:"recipient" validate:"required,solana_pubkey"`
}

func (s *Service) sessionCloseExpiredSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req sessionCloseExpiredRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	recipient, err := solana.PublicKeyFromBase58(req.Recipient)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "recipient: "+err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	mainIx, err := CloseExpiredSession(CloseExpiredSessionParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		Recipient:         recipient,
		InitAuthorityHash: initHash,
		SessionIndex:      req.SessionIndex,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	sigOut, err := s.GasSponsor.SignAndSend(r.Context(), []solana.Instruction{mainIx})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}
	extra := fmt.Sprintf(`{"session_index":%d,"recipient":"%s"}`, req.SessionIndex, recipient.String())
	s.appendAuditSubmit(r, "session.close-expired", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// ── shared helpers for the per-session admin path ───────────────────────────

func (s *Service) adminPrecompile(w http.ResponseWriter, ownerSlot [MemberSlotLen]byte, challenge [32]byte,
	sigB64, webauthnAuthDataB64, webauthnCDJB64 string) (solana.Instruction, bool) {
	sig, err := base64Decode(sigB64)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "signature_base64: "+err.Error())
		return nil, true
	}
	var authData, cdj []byte
	if webauthnAuthDataB64 != "" {
		if authData, err = base64Decode(webauthnAuthDataB64); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "webauthn_auth_data_base64: "+err.Error())
			return nil, true
		}
	}
	if webauthnCDJB64 != "" {
		if cdj, err = base64Decode(webauthnCDJB64); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "webauthn_cdj_base64: "+err.Error())
			return nil, true
		}
	}
	ix, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return nil, true
	}
	return ix, false
}

func (s *Service) sendSessionAdminTx(w http.ResponseWriter, r *http.Request, d *sessionDerived, ixs []solana.Instruction, action, extra string) {
	sigOut, err := s.GasSponsor.SignAndSend(r.Context(), ixs)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}
	s.appendAuditSubmit(r, action, d.engine.String(), d.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: d.engine.String(),
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func leU32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func leU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// ─── /v1/policy/session/use/build ───────────────────────────────────────────

// sessionUseBuildRequest carries the inputs needed to assemble the disc 101
// instruction. The gateway DOES NOT sign or send this tx — the dev receives
// the instruction, builds their own Solana tx, signs with the session-signer
// keypair (which Andromeda never sees), pays gas themselves, and broadcasts.
type sessionUseBuildRequest struct {
	DwalletAddress      string `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash   string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	SessionIndex        uint32 `json:"session_index" validate:"max=255"`
	SessionSignerPubkey string `json:"session_signer_pubkey" validate:"required,solana_pubkey"`
	MessageDigestHex    string `json:"message_digest_hex" validate:"required,hex_len=32"`
	MetadataDigestHex   string `json:"metadata_digest_hex" validate:"required,hex_len=32"`
	UserPubkeyHex       string `json:"user_pubkey_hex" validate:"required,hex_len=32"`
	SignatureScheme     uint16 `json:"signature_scheme" validate:"max=6"`
	IkaCurve            uint16 `json:"ika_curve" validate:"max=2"`
	IkaDWalletPubkeyHex string `json:"ika_dwallet_pubkey_hex" validate:"required"`
	DestinationHex      string `json:"destination_hex" validate:"required,hex_len=32"`
	ExpectedNonce       uint64 `json:"expected_signature_nonce"`
	Amount              uint64 `json:"amount,omitempty"`
	// Payer is the on-chain account that pays the tx fee (the dev's wallet,
	// or any keypair they control). The session-signer MUST also sign the tx
	// alongside this payer — Andromeda never holds either.
	Payer string `json:"payer" validate:"required,solana_pubkey"`
}

type sessionUseBuildResponse struct {
	EngineAddress  string          `json:"engine_address"`
	SessionAddress string          `json:"session_address"`
	Instruction    instructionJSON `json:"request_signature_via_session_instruction"`
	Notice         string          `json:"notice"`
}

func (s *Service) sessionUseBuild(w http.ResponseWriter, r *http.Request) {
	var req sessionUseBuildRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	sessionSigner, err := solana.PublicKeyFromBase58(req.SessionSignerPubkey)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "session_signer_pubkey: "+err.Error())
		return
	}
	payer, err := solana.PublicKeyFromBase58(req.Payer)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "payer: "+err.Error())
		return
	}
	msgDigest, _ := mustHex32(req.MessageDigestHex)
	metaDigest, _ := mustHex32(req.MetadataDigestHex)
	userPK, _ := mustHex32(req.UserPubkeyHex)
	dest, _ := mustHex32(req.DestinationHex)

	ikaPK, err := hex.DecodeString(req.IkaDWalletPubkeyHex)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "ika_dwallet_pubkey_hex must be 1..96-byte hex")
		return
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	cpiAuth, cpiBump, err := CPIAuthorityPDA(s.ProgramID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	// disc 101 uses zero metadata seed (no Ika message_metadata_digest path here —
	// Andromeda Zcash flows still go through disc 1).
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:], make([]byte, 32),
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	// caller_program MUST be unique vs program (same constraint as disc 1).
	callerProgram := solana.NewWallet().PublicKey()
	sessionPDA, _, err := SessionPDA(s.ProgramID, engine, req.SessionIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	mainIx, err := RequestSignatureViaSession(RequestSignatureViaSessionParams{
		ProgramID:              s.ProgramID,
		Engine:                 engine,
		DWallet:                dwallet,
		Coordinator:            IkaCoordinator(),
		MessageApproval:        msgApproval,
		Payer:                  payer,
		CPIAuthority:           cpiAuth,
		CallerProgram:          callerProgram,
		DWalletProgram:         IkaDwalletProgramID,
		SessionSigner:          sessionSigner,
		InitAuthorityHash:      initHash,
		SessionIndex:           req.SessionIndex,
		MessageDigest:          msgDigest,
		MetadataDigest:         metaDigest,
		UserPubkey:             userPK,
		SignatureScheme:        req.SignatureScheme,
		MessageApprovalBump:    msgApprovalBump,
		CPIAuthorityBump:       cpiBump,
		Destination:            dest,
		ExpectedSignatureNonce: req.ExpectedNonce,
		Amount:                 req.Amount,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	ixJSON, err := serializeInstruction(mainIx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "serialize_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionUseBuildResponse{
		EngineAddress:  engine.String(),
		SessionAddress: sessionPDA.String(),
		Instruction:    ixJSON,
		Notice:         "build-only: the session signer + payer MUST sign the resulting tx. Andromeda does NOT custody either. Use Auto Resolution / Rule PDAs separately if APPLIES_SESSION rules are active on this engine.",
	})
}

// ─── /v1/policy/session/{engine}/{sessionIndex} (read) ──────────────────────

type sessionReadResponse struct {
	EngineAddress         string   `json:"engine_address"`
	SessionAddress        string   `json:"session_address"`
	SessionSignerPubkey   string   `json:"session_signer_pubkey"`
	SessionIndex          uint32   `json:"session_index"`
	CreatedAtTs           int64    `json:"created_at_ts"`
	ExpiresAtTs           int64    `json:"expires_at_ts"`
	UsedCount             uint32   `json:"used_count"`
	MaxUses               uint32   `json:"max_uses"`
	NextSignatureNonce    uint64   `json:"next_signature_nonce"`
	MaxAmountPerTx        uint64   `json:"max_amount_per_tx"`
	NextAdminNonce        uint64   `json:"next_admin_nonce"`
	Destinations          []string `json:"destinations_hex"`
}

// sessionReadHandler returns the on-chain state of a Session PDA. The dev
// passes the engine pubkey (base58) and session_index in the path. Read-only —
// no signing, no gas.
//
// Layout mirror (contracts/policy-engine/src/lib.rs::Session,
// `#[account(discriminator = 3)]`). Quasar uses a 1-byte account discriminator
// at offset 0 (matches DecodePolicyEngine / DecodeAllowlistRule in codecs.go,
// which also start at `data[0]`). The struct fields follow immediately:
//
//	off 0:   account_discriminator (1, = 3)
//	off 1:   engine (32)
//	off 33:  session_signer (32)
//	off 65:  session_index (u32 LE)
//	off 69:  _pad0 (u32)
//	off 73:  created_at_ts (i64 LE)
//	off 81:  expires_at_ts (i64 LE)
//	off 89:  used_count (u32 LE)
//	off 93:  max_uses (u32 LE)
//	off 97:  next_signature_nonce (u64 LE)
//	off 105: max_amount_per_tx (u64 LE)
//	off 113: next_admin_nonce (u64 LE)
//	off 121: destinations_count (u8)
//	off 122: _pad_cfg (7)
//	off 129: destinations_flat (8 × 32 = 256)
//
// Total: 129 + 256 = 385 bytes.
func (s *Service) sessionReadHandler(w http.ResponseWriter, r *http.Request, engineStr, sessionIdxStr string) {
	engine, err := solana.PublicKeyFromBase58(engineStr)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "engine: "+err.Error())
		return
	}
	idxParsed, parseErr := strconv.ParseUint(sessionIdxStr, 10, 32)
	if parseErr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "session_index must be a decimal integer")
		return
	}
	sessionIndex := uint32(idxParsed)
	if s.RPCClient == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "no_rpc", "SOLANA_RPC_URL is not configured")
		return
	}
	sessionPDA, _, err := SessionPDA(s.ProgramID, engine, sessionIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	acct, err := s.RPCClient.GetAccountInfo(r.Context(), sessionPDA)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "rpc_failed", err.Error())
		return
	}
	if acct == nil || acct.Value == nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "session PDA not found on-chain")
		return
	}
	data := acct.Value.Data.GetBinary()
	resp, perr := parseSessionAccount(data, engine, sessionPDA)
	if perr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "decode_failed", perr.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// SessionAccountBytes is the total byte length of a Session PDA (1-byte disc +
// 384-byte struct). Exposed for tests + parse defensive guard.
const SessionAccountBytes = 1 + 32 + 32 + 4 + 4 + 8 + 8 + 4 + 4 + 8 + 8 + 8 + 1 + 7 + 8*32

func parseSessionAccount(data []byte, engine, sessionPDA solana.PublicKey) (*sessionReadResponse, error) {
	if len(data) < SessionAccountBytes {
		return nil, fmt.Errorf("session account too short: %d < %d", len(data), SessionAccountBytes)
	}
	if data[0] != 3 {
		return nil, fmt.Errorf("session account discriminator = %d (expected 3)", data[0])
	}
	// Defense in depth: the engine the PDA was derived against MUST equal the
	// engine bytes stored in the account. A mismatch would indicate either a
	// wrong PDA derivation, a layout shift, or a tampered account.
	var engineOnChain [32]byte
	copy(engineOnChain[:], data[1:33])
	if engineOnChain != [32]byte(engine) {
		return nil, fmt.Errorf("session account engine mismatch (PDA-derived vs on-chain)")
	}
	signerBytes := data[33:65]
	sessionIndex := leDecodeU32(data[65:69])
	// off 69..73 is _pad0 (skipped)
	createdAt := int64(leDecodeU64(data[73:81]))
	expiresAt := int64(leDecodeU64(data[81:89]))
	usedCount := leDecodeU32(data[89:93])
	maxUses := leDecodeU32(data[93:97])
	nextSigNonce := leDecodeU64(data[97:105])
	maxAmount := leDecodeU64(data[105:113])
	nextAdminNonce := leDecodeU64(data[113:121])
	destCount := int(data[121])
	// off 122..129 is _pad_cfg (skipped)
	if destCount > 8 {
		destCount = 8 // defensive — on-chain enforces this, but trim anyway
	}
	dests := make([]string, 0, destCount)
	for i := 0; i < destCount; i++ {
		off := 129 + i*32
		dests = append(dests, hex.EncodeToString(data[off:off+32]))
	}
	return &sessionReadResponse{
		EngineAddress:       engine.String(),
		SessionAddress:      sessionPDA.String(),
		SessionSignerPubkey: solana.PublicKeyFromBytes(signerBytes).String(),
		SessionIndex:        sessionIndex,
		CreatedAtTs:         createdAt,
		ExpiresAtTs:         expiresAt,
		UsedCount:           usedCount,
		MaxUses:             maxUses,
		NextSignatureNonce:  nextSigNonce,
		MaxAmountPerTx:      maxAmount,
		NextAdminNonce:      nextAdminNonce,
		Destinations:        dests,
	}, nil
}

func leDecodeU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leDecodeU64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// ─── op tags (mirror of contracts/policy-engine/src/lib.rs) ─────────────────

// These are the byte slices the on-chain `admin_challenge(...)` expects as the
// `op_tag`. Kept here (next to the handlers that use them) rather than in
// `challenges.go` because they are session-lifecycle-specific.
var (
	OpSessionOpen       = []byte("session-open")
	OpSessionRevoke     = []byte("session-revoke")
	OpSessionClose      = []byte("session-close")
	OpSessionAddDest    = []byte("session-add-destination")
	OpSessionRemoveDest = []byte("session-remove-destination")
)

