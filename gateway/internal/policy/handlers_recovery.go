package policy

import (
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// F11b-Phase1 — recover_as_primary HTTP surface.
//
// Two endpoints mirror the challenge/submit pair already established by the
// allowlist flow:
//
//	POST /v1/policy/recover-as-primary/challenge → returns the 32-byte hash the
//	                                                primary credential signs
//	                                                + the rendered clear-signing
//	                                                message
//	POST /v1/policy/recover-as-primary/submit    → consumes the signature, builds
//	                                                [credential precompile + main
//	                                                ix], and lands the tx via the
//	                                                gas sponsor
//
// Companion flows (quorum_session_*, passkey_session_*, oidc_*) follow the
// same template and ship in subsequent F11b phases — once this slice is
// validated on devnet, the rest is largely repetition.

// ── /v1/policy/recover-as-primary/challenge ──────────────────────────────────

type recoverAsPrimaryChallengeRequest struct {
	DwalletAddress      string         `json:"dwallet_address"        validate:"required,solana_pubkey"`
	InitAuthorityHash   string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	PrimarySlot         memberSlotJSON `json:"primary_slot"            validate:"required"`
	MessageDigestHex    string         `json:"message_digest_hex"      validate:"required,hex_len=32"`
	MetadataDigestHex   string         `json:"metadata_digest_hex"     validate:"required,hex_len=32"`
	UserPubkeyHex       string         `json:"user_pubkey_hex"         validate:"required,hex_len=32"`
	SignatureScheme     uint16         `json:"signature_scheme"        validate:"max=6"`
	DestinationHex      string         `json:"destination_hex"         validate:"required,hex_len=32"`
	RuleIndex           uint8          `json:"rule_index"              validate:"max=15"`
	ExpectedNonce       uint64         `json:"expected_nonce"`
	IkaCurve            uint16         `json:"ika_curve"               validate:"max=2"`
	IkaDWalletPubkey    string         `json:"ika_dwallet_pubkey_hex"  validate:"required"`
}

type recoverAsPrimaryChallengeResponse struct {
	ProgramID                 string `json:"program_id"`
	EngineAddress             string `json:"engine_address"`
	RulePDA                   string `json:"rule_pda"`
	MessageApprovalAddress    string `json:"message_approval_address"`
	MessageApprovalBump       uint8  `json:"message_approval_bump"`
	OpTag                     string `json:"op_tag"`
	HumanMessage              string `json:"human_message"`
	PreimageHex               string `json:"preimage_hex"`
	ChallengeHex              string `json:"challenge_hex"`
	PrimaryScheme             uint8  `json:"primary_scheme"`
}

func (s *Service) recoverAsPrimaryChallenge(w http.ResponseWriter, r *http.Request) {
	var req recoverAsPrimaryChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.deriveRecoverAsPrimary(&req)
	if derr != nil {
		derr.write(w)
		return
	}

	in := &PrimaryRecoverChallengeInput{
		DWallet:             derived.dwallet,
		MessageApproval:     derived.msgApproval,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		Nonce:               req.ExpectedNonce,
		PrimarySlot:         derived.primarySlot,
	}
	preimage, err := in.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	hash, _ := in.Hash()
	human := HumanMessagePrimaryRecover(
		derived.dwallet, derived.msgDigest, derived.metaDigest, derived.userPubkey, req.SignatureScheme,
	)

	httpx.WriteJSON(w, http.StatusOK, recoverAsPrimaryChallengeResponse{
		ProgramID:              s.ProgramID.String(),
		EngineAddress:          derived.engine.String(),
		RulePDA:                derived.rulePDA.String(),
		MessageApprovalAddress: derived.msgApproval.String(),
		MessageApprovalBump:    derived.msgApprovalBump,
		OpTag:                  string(OpTagPrimaryRecover),
		HumanMessage:           string(human),
		PreimageHex:            hex.EncodeToString(preimage),
		ChallengeHex:           hex.EncodeToString(hash[:]),
		PrimaryScheme:          derived.primarySlot[0],
	})
}

// ── /v1/policy/recover-as-primary/submit ─────────────────────────────────────

type recoverAsPrimarySubmitRequest struct {
	signedSubmitFields
	recoverAsPrimaryChallengeRequest
	Amount uint64 `json:"amount"`
}

func (s *Service) recoverAsPrimarySubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req recoverAsPrimarySubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	derived, derr := s.deriveRecoverAsPrimary(&req.recoverAsPrimaryChallengeRequest)
	if derr != nil {
		derr.write(w)
		return
	}

	in := &PrimaryRecoverChallengeInput{
		DWallet:             derived.dwallet,
		MessageApproval:     derived.msgApproval,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		Nonce:               req.ExpectedNonce,
		PrimarySlot:         derived.primarySlot,
	}
	challenge, err := in.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}

	precompile, err := buildCredentialPrecompile(derived.primarySlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}

	// `caller_program` MUST NOT equal `program` (Quasar / SVM rejects with
	// AccountBorrowFailed when duplicated). The on-chain Ika mock ignores the
	// semantic value of caller_program; real Ika does not validate it either.
	// This matches the existing pattern in `requestSignatureSubmit`.
	callerProgram := solana.NewWallet().PublicKey()

	mainIx, err := RecoverAsPrimary(RecoverAsPrimaryParams{
		ProgramID:           s.ProgramID,
		Engine:              derived.engine,
		DWallet:             derived.dwallet,
		Coordinator:         derived.dwallet, // F2.6c placeholder — real coordinator lookup is F9
		MessageApproval:     derived.msgApproval,
		Payer:               s.GasSponsor.PublicKey(),
		CPIAuthority:        derived.cpiAuthority,
		CallerProgram:       callerProgram,
		DWalletProgram:      IkaDwalletProgramID,
		InitAuthorityHash:   derived.initHash,
		RuleIndex:           req.RuleIndex,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		CPIAuthorityBump:    derived.cpiAuthorityBump,
		Destination:         derived.destination,
		ExpectedNonce:       req.ExpectedNonce,
		Amount:              req.Amount,
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
	extra := fmt.Sprintf(`{"signature_scheme":%d,"rule_index":%d,"amount":%d}`,
		req.SignatureScheme, req.RuleIndex, req.Amount)
	s.appendAuditSubmit(r, "recover-as-primary",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)

	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── shared derivation helper ─────────────────────────────────────────────────

type recoverAsPrimaryDerived struct {
	dwallet          solana.PublicKey
	initHash         [32]byte
	engine           solana.PublicKey
	rulePDA          solana.PublicKey
	primarySlot      [MemberSlotLen]byte
	msgDigest        [32]byte
	metaDigest       [32]byte
	userPubkey       [32]byte
	destination      [32]byte
	msgApproval      solana.PublicKey
	msgApprovalBump  uint8
	cpiAuthority     solana.PublicKey
	cpiAuthorityBump uint8
}

// httpError is a small typed error carrier that lets the derivation helper
// short-circuit with a status code without each call site repeating the
// `httpx.WriteError + return` pair.
type httpError struct {
	status int
	code   string
	msg    string
}

func (e *httpError) write(w http.ResponseWriter) {
	httpx.WriteError(w, e.status, e.code, e.msg)
}

func (s *Service) deriveRecoverAsPrimary(
	req *recoverAsPrimaryChallengeRequest,
) (*recoverAsPrimaryDerived, *httpError) {
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "dwallet_address: " + err.Error()}
	}
	initHash, err := mustHex32(req.InitAuthorityHash)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "init_authority_hash_hex: " + err.Error()}
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "primary_slot: " + err.Error()}
	}
	msgDigest, err := mustHex32(req.MessageDigestHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "message_digest_hex: " + err.Error()}
	}
	metaDigest, err := mustHex32(req.MetadataDigestHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "metadata_digest_hex: " + err.Error()}
	}
	userPubkey, err := mustHex32(req.UserPubkeyHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "user_pubkey_hex: " + err.Error()}
	}
	destination, err := mustHex32(req.DestinationHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "destination_hex: " + err.Error()}
	}
	ikaPK, err := decodeHex(req.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		return nil, &httpError{http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)"}
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindRecovery, req.RuleIndex)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	cpiAuth, cpiBump, err := CPIAuthorityPDA(s.ProgramID)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:], metaDigest[:],
	)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}

	return &recoverAsPrimaryDerived{
		dwallet:          dwallet,
		initHash:         initHash,
		engine:           engine,
		rulePDA:          rulePDA,
		primarySlot:      primarySlot,
		msgDigest:        msgDigest,
		metaDigest:       metaDigest,
		userPubkey:       userPubkey,
		destination:      destination,
		msgApproval:      msgApproval,
		msgApprovalBump:  msgApprovalBump,
		cpiAuthority:     cpiAuth,
		cpiAuthorityBump: cpiBump,
	}, nil
}
