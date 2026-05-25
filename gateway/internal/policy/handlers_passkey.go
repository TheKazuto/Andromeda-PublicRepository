package policy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// F11b-Phase2 — passkey_session_* HTTP surface.
//
//	POST /v1/policy/passkey/session/open/challenge   passkey signs (Secp256r1+WebAuthn)
//	POST /v1/policy/passkey/session/open/submit
//	POST /v1/policy/passkey/use/challenge            ephemeral Ed25519 signs
//	POST /v1/policy/passkey/use/submit
//	POST /v1/policy/passkey/session/close            recipient signs (rent reclaim)

// ── shared inputs ────────────────────────────────────────────────────────────

type passkeyCommonInputs struct {
	DwalletAddress      string `json:"dwallet_address"          validate:"required,solana_pubkey"`
	InitAuthorityHash   string `json:"init_authority_hash_hex"  validate:"required,hex_len=32"`
	RuleIndex           uint8  `json:"rule_index"               validate:"max=15"`
	PasskeySessionNonce uint64 `json:"passkey_session_nonce"`
}

type passkeyDerived struct {
	dwallet    solana.PublicKey
	initHash   [32]byte
	engine     solana.PublicKey
	rulePDA    solana.PublicKey
	sessionPDA solana.PublicKey
}

func (s *Service) derivePasskey(in *passkeyCommonInputs) (*passkeyDerived, *httpError) {
	dwallet, err := solana.PublicKeyFromBase58(in.DwalletAddress)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "dwallet_address: " + err.Error()}
	}
	initHash, err := mustHex32(in.InitAuthorityHash)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "init_authority_hash_hex: " + err.Error()}
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindRecovery, in.RuleIndex)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	sessionPDA, _, err := PasskeySessionPDA(s.ProgramID, engine, in.PasskeySessionNonce)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	return &passkeyDerived{
		dwallet:    dwallet,
		initHash:   initHash,
		engine:     engine,
		rulePDA:    rulePDA,
		sessionPDA: sessionPDA,
	}, nil
}

// ── /v1/policy/passkey/session/open/{challenge,submit} ──────────────────────

type passkeyOpenChallengeRequest struct {
	passkeyCommonInputs
	PrimarySlot         memberSlotJSON `json:"primary_slot"           validate:"required"`
	EphPkHex            string         `json:"eph_pk_hex"             validate:"required,hex_len=32"`
	NotAfterUnixTs      uint64         `json:"not_after_unix_ts"`
	CredentialIDHashHex string         `json:"credential_id_hash_hex" validate:"required,hex_len=32"`
}

type passkeyOpenChallengeResponse struct {
	ProgramID      string `json:"program_id"`
	EngineAddress  string `json:"engine_address"`
	SessionAddress string `json:"session_address"`
	OpTag          string `json:"op_tag"`
	HumanMessage   string `json:"human_message"`
	PreimageHex    string `json:"preimage_hex"`
	ChallengeHex   string `json:"challenge_hex"`
}

func (s *Service) passkeyOpenChallenge(w http.ResponseWriter, r *http.Request) {
	var req passkeyOpenChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.derivePasskey(&req.passkeyCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}
	if primarySlot[0] != 3 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"primary_slot must use scheme=3 (WebAuthn) for passkey sessions")
		return
	}
	ephPk, err := mustHex32(req.EphPkHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "eph_pk_hex: "+err.Error())
		return
	}
	credIDHash, err := mustHex32(req.CredentialIDHashHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "credential_id_hash_hex: "+err.Error())
		return
	}

	in := &PasskeySessionOpenChallengeInput{
		DWallet:          derived.dwallet,
		PrimarySlot:      primarySlot,
		EphPk:            ephPk,
		NotAfterUnixTs:   req.NotAfterUnixTs,
		CredentialIDHash: credIDHash,
		SessionNonce:     req.PasskeySessionNonce,
	}
	preimage, err := in.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	hash, _ := in.Hash()
	human := HumanMessagePasskeySessionOpen(derived.dwallet, req.NotAfterUnixTs, ephPk)

	httpx.WriteJSON(w, http.StatusOK, passkeyOpenChallengeResponse{
		ProgramID:      s.ProgramID.String(),
		EngineAddress:  derived.engine.String(),
		SessionAddress: derived.sessionPDA.String(),
		OpTag:          string(OpTagPasskeySessionOpen),
		HumanMessage:   string(human),
		PreimageHex:    hex.EncodeToString(preimage),
		ChallengeHex:   hex.EncodeToString(hash[:]),
	})
}

type passkeyOpenSubmitRequest struct {
	signedSubmitFields
	passkeyOpenChallengeRequest
	WebauthnAuthDataBase64       string `json:"webauthn_auth_data_base64"         validate:"required,base64"`
	WebauthnClientDataJSONBase64 string `json:"webauthn_client_data_json_base64"  validate:"required,base64"`
	ExpectedPasskeySessionNonce  uint64 `json:"expected_passkey_session_nonce"`
}

func (s *Service) passkeyOpenSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req passkeyOpenSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, _, _, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	// Passkey open requires the WebAuthn pair carried in the request body,
	// not the signedSubmitFields helper fields — the on-chain handler verifies
	// auth_data || sha256(clientDataJSON) via the Secp256r1 precompile.
	authData, err := base64.StdEncoding.DecodeString(req.WebauthnAuthDataBase64)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "webauthn_auth_data_base64: "+err.Error())
		return
	}
	cdj, err := base64.StdEncoding.DecodeString(req.WebauthnClientDataJSONBase64)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "webauthn_client_data_json_base64: "+err.Error())
		return
	}
	derived, derr := s.derivePasskey(&req.passkeyCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}
	if primarySlot[0] != 3 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"primary_slot must use scheme=3 (WebAuthn)")
		return
	}
	ephPk, err := mustHex32(req.EphPkHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "eph_pk_hex: "+err.Error())
		return
	}
	credIDHash, err := mustHex32(req.CredentialIDHashHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "credential_id_hash_hex: "+err.Error())
		return
	}

	in := &PasskeySessionOpenChallengeInput{
		DWallet:          derived.dwallet,
		PrimarySlot:      primarySlot,
		EphPk:            ephPk,
		NotAfterUnixTs:   req.NotAfterUnixTs,
		CredentialIDHash: credIDHash,
		SessionNonce:     req.PasskeySessionNonce,
	}
	challenge, err := in.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	// Secp256r1 + WebAuthn precompile: the credential signs auth_data ||
	// sha256(clientDataJSON), where clientDataJSON.challenge embeds the
	// canonical `challenge` above (base64url, no padding).
	precompile, err := buildCredentialPrecompile(primarySlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := PasskeySessionOpen(PasskeySessionOpenParams{
		ProgramID:                   s.ProgramID,
		Engine:                      derived.engine,
		DWallet:                     derived.dwallet,
		Payer:                       s.GasSponsor.PublicKey(),
		InitAuthorityHash:           derived.initHash,
		RuleIndex:                   req.RuleIndex,
		PasskeySessionNonce:         req.PasskeySessionNonce,
		EphPk:                       ephPk,
		NotAfterUnixTs:              req.NotAfterUnixTs,
		CredentialIdHash:            credIDHash,
		ExpectedPasskeySessionNonce: req.ExpectedPasskeySessionNonce,
		WebAuthnAuthData:            authData,
		WebAuthnClientDataJSON:      cdj,
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
	extra := fmt.Sprintf(`{"passkey_session_nonce":%d}`, req.PasskeySessionNonce)
	s.appendAuditSubmit(r, "passkey.session.open",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── /v1/policy/passkey/use/{challenge,submit} ───────────────────────────────

type passkeyUseChallengeRequest struct {
	passkeyCommonInputs
	// PrimarySlot is the WebAuthn slot bound to the session (scheme=3,
	// credential pubkey). The challenge BINDS to this slot so the on-chain
	// handler can re-verify the session was opened by the same credential.
	PrimarySlot memberSlotJSON `json:"primary_slot"           validate:"required"`
	// EphPkHex is the ephemeral Ed25519 pubkey (32 bytes hex). The user's
	// device signed the challenge with the matching secret key; the gateway
	// uses this to build the Ed25519 precompile.
	EphPkHex          string `json:"eph_pk_hex"             validate:"required,hex_len=32"`
	MessageDigestHex  string `json:"message_digest_hex"     validate:"required,hex_len=32"`
	MetadataDigestHex string `json:"metadata_digest_hex"    validate:"required,hex_len=32"`
	UserPubkeyHex     string `json:"user_pubkey_hex"        validate:"required,hex_len=32"`
	SignatureScheme   uint16 `json:"signature_scheme"       validate:"max=6"`
	UseNonce          uint64 `json:"use_nonce"`
	IkaCurve          uint16 `json:"ika_curve"              validate:"max=2"`
	IkaDWalletPubkey  string `json:"ika_dwallet_pubkey_hex" validate:"required"`
}

type passkeyUseChallengeResponse struct {
	ProgramID              string `json:"program_id"`
	EngineAddress          string `json:"engine_address"`
	SessionAddress         string `json:"session_address"`
	MessageApprovalAddress string `json:"message_approval_address"`
	MessageApprovalBump    uint8  `json:"message_approval_bump"`
	OpTag                  string `json:"op_tag"`
	HumanMessage           string `json:"human_message"`
	PreimageHex            string `json:"preimage_hex"`
	ChallengeHex           string `json:"challenge_hex"`
}

func (s *Service) passkeyUseChallenge(w http.ResponseWriter, r *http.Request) {
	var req passkeyUseChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.derivePasskey(&req.passkeyCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}
	msgDigest, err := mustHex32(req.MessageDigestHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "message_digest_hex: "+err.Error())
		return
	}
	metaDigest, err := mustHex32(req.MetadataDigestHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "metadata_digest_hex: "+err.Error())
		return
	}
	userPubkey, err := mustHex32(req.UserPubkeyHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "user_pubkey_hex: "+err.Error())
		return
	}
	ikaPK, err := hex.DecodeString(req.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)")
		return
	}
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:], nil, // recovery: no Ika signing metadata
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	in := &PasskeyPrimaryUseChallengeInput{
		Session:             derived.sessionPDA,
		DWallet:             derived.dwallet,
		MessageApproval:     msgApproval,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: msgApprovalBump,
		UseNonce:            req.UseNonce,
		PrimarySlot:         primarySlot,
	}
	preimage, err := in.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	hash, _ := in.Hash()
	human := HumanMessagePasskeyPrimaryUse(
		derived.sessionPDA, derived.dwallet, msgDigest, metaDigest, userPubkey, req.SignatureScheme,
	)

	httpx.WriteJSON(w, http.StatusOK, passkeyUseChallengeResponse{
		ProgramID:              s.ProgramID.String(),
		EngineAddress:          derived.engine.String(),
		SessionAddress:         derived.sessionPDA.String(),
		MessageApprovalAddress: msgApproval.String(),
		MessageApprovalBump:    msgApprovalBump,
		OpTag:                  string(OpTagPasskeyPrimaryUse),
		HumanMessage:           string(human),
		PreimageHex:            hex.EncodeToString(preimage),
		ChallengeHex:           hex.EncodeToString(hash[:]),
	})
}

type passkeyUseSubmitRequest struct {
	signedSubmitFields
	passkeyUseChallengeRequest
	ExpectedUseNonce uint64 `json:"expected_use_nonce"`
}

func (s *Service) passkeyUseSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req passkeyUseSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	derived, derr := s.derivePasskey(&req.passkeyCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}
	msgDigest, err := mustHex32(req.MessageDigestHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "message_digest_hex: "+err.Error())
		return
	}
	metaDigest, err := mustHex32(req.MetadataDigestHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "metadata_digest_hex: "+err.Error())
		return
	}
	userPubkey, err := mustHex32(req.UserPubkeyHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "user_pubkey_hex: "+err.Error())
		return
	}
	ikaPK, err := hex.DecodeString(req.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)")
		return
	}
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:], nil, // recovery: no Ika signing metadata
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	cpiAuth, cpiBump, err := CPIAuthorityPDA(s.ProgramID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	in := &PasskeyPrimaryUseChallengeInput{
		Session:             derived.sessionPDA,
		DWallet:             derived.dwallet,
		MessageApproval:     msgApproval,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: msgApprovalBump,
		UseNonce:            req.UseNonce,
		PrimarySlot:         primarySlot,
	}
	challenge, err := in.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	// `use` is signed by the ephemeral Ed25519. The precompile checks
	// (eph_pk, challenge, sig); the on-chain handler then matches eph_pk
	// against `session.eph_pk` for binding. We wrap eph_pk as a synthetic
	// Ed25519 slot (scheme=0, padding to 34 bytes) just to reuse the
	// existing credential-precompile builder.
	ephPk, err := mustHex32(req.EphPkHex)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "eph_pk_hex: "+err.Error())
		return
	}
	var ephSlot [MemberSlotLen]byte
	ephSlot[0] = 0
	copy(ephSlot[1:33], ephPk[:])
	precompile, err := buildCredentialPrecompile(ephSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	_ = primarySlot // referenced for clarity in the challenge binding above

	callerProgram := solana.NewWallet().PublicKey()
	mainIx, err := RecoverAsPrimaryPasskeySession(RecoverAsPrimaryPasskeySessionParams{
		ProgramID:           s.ProgramID,
		Engine:              derived.engine,
		DWallet:             derived.dwallet,
		Coordinator:         IkaCoordinator(),
		MessageApproval:     msgApproval,
		Payer:               s.GasSponsor.PublicKey(),
		CPIAuthority:        cpiAuth,
		CallerProgram:       callerProgram,
		DWalletProgram:      IkaDwalletProgramID,
		InitAuthorityHash:   derived.initHash,
		RuleIndex:           req.RuleIndex,
		PasskeySessionNonce: req.PasskeySessionNonce,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: msgApprovalBump,
		CPIAuthorityBump:    cpiBump,
		ExpectedUseNonce:    req.ExpectedUseNonce,
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
	extra := fmt.Sprintf(`{"passkey_session_nonce":%d,"use_nonce":%d}`,
		req.PasskeySessionNonce, req.UseNonce)
	s.appendAuditSubmit(r, "passkey.use",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── /v1/policy/passkey/session/close (recipient signs — Phase2b unsigned-tx) ─
//
// Same shape as quorum close: the gateway builds the close ix + fetches a
// recent blockhash, returns the unsigned tx; the recipient signs client-side
// and submits via Solana RPC.

type passkeyCloseRequest struct {
	DwalletAddress      string `json:"dwallet_address"          validate:"required,solana_pubkey"`
	InitAuthorityHash   string `json:"init_authority_hash_hex"  validate:"required,hex_len=32"`
	PasskeySessionNonce uint64 `json:"passkey_session_nonce"`
	Recipient           string `json:"recipient_address"        validate:"required,solana_pubkey"`
}

func (s *Service) passkeyClose(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req passkeyCloseRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "dwallet_address: "+err.Error())
		return
	}
	initHash, err := mustHex32(req.InitAuthorityHash)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "init_authority_hash_hex: "+err.Error())
		return
	}
	recipient, err := solana.PublicKeyFromBase58(req.Recipient)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "recipient_address: "+err.Error())
		return
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	sessionPDA, _, err := PasskeySessionPDA(s.ProgramID, engine, req.PasskeySessionNonce)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	closeIx, err := PasskeySessionClose(PasskeySessionCloseParams{
		ProgramID:           s.ProgramID,
		Engine:              engine,
		DWallet:             dwallet,
		Recipient:           recipient,
		InitAuthorityHash:   initHash,
		PasskeySessionNonce: req.PasskeySessionNonce,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	resp, herr := s.buildUnsignedTx(r, recipient, []solana.Instruction{closeIx},
		map[string]any{
			"engine_address":        engine.String(),
			"session_address":       sessionPDA.String(),
			"passkey_session_nonce": req.PasskeySessionNonce,
		})
	if herr != nil {
		herr.write(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
