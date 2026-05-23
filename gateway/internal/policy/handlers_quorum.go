package policy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// F11b-Phase2 — quorum_session_* HTTP surface.
//
// Six endpoints map the on-chain quorum recovery flow (M-of-N):
//
//	POST /v1/policy/quorum/session/open/challenge        primary signs
//	POST /v1/policy/quorum/session/open/submit
//	POST /v1/policy/quorum/session/contribute/challenge  member signs
//	POST /v1/policy/quorum/session/contribute/submit
//	POST /v1/policy/quorum/session/finalize              permissionless (no signature)
//	POST /v1/policy/quorum/session/close                 recipient signs tx + receives rent
//
// Patterns are inherited from handlers_recovery.go: each `*/challenge` returns
// the canonical bytes the credential signs off-chain; each `*/submit` consumes
// the signature, builds [precompile + main ix], lands the tx, and audits.

// ── shared inputs for quorum endpoints ───────────────────────────────────────

type quorumCommonInputs struct {
	DwalletAddress    string `json:"dwallet_address"        validate:"required,solana_pubkey"`
	InitAuthorityHash string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	MessageDigestHex  string `json:"message_digest_hex"     validate:"required,hex_len=32"`
	MetadataDigestHex string `json:"metadata_digest_hex"    validate:"required,hex_len=32"`
	UserPubkeyHex     string `json:"user_pubkey_hex"        validate:"required,hex_len=32"`
	DestinationHex    string `json:"destination_hex"        validate:"required,hex_len=32"`
	SignatureScheme   uint16 `json:"signature_scheme"       validate:"max=6"`
	Amount            uint64 `json:"amount"`
	ExpiresAt         int64  `json:"expires_at"`
	SessionNonce      uint64 `json:"session_nonce"`
	RuleIndex         uint8  `json:"rule_index"             validate:"max=15"`
	IkaCurve          uint16 `json:"ika_curve"              validate:"max=2"`
	IkaDWalletPubkey  string `json:"ika_dwallet_pubkey_hex" validate:"required"`
}

type quorumDerived struct {
	dwallet          solana.PublicKey
	initHash         [32]byte
	engine           solana.PublicKey
	rulePDA          solana.PublicKey
	sessionPDA       solana.PublicKey
	msgDigest        [32]byte
	metaDigest       [32]byte
	userPubkey       [32]byte
	destination      [32]byte
	msgApproval      solana.PublicKey
	msgApprovalBump  uint8
	cpiAuthority     solana.PublicKey
	cpiAuthorityBump uint8
}

func (s *Service) deriveQuorum(in *quorumCommonInputs) (*quorumDerived, *httpError) {
	dwallet, err := solana.PublicKeyFromBase58(in.DwalletAddress)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "dwallet_address: " + err.Error()}
	}
	initHash, err := mustHex32(in.InitAuthorityHash)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "init_authority_hash_hex: " + err.Error()}
	}
	msgDigest, err := mustHex32(in.MessageDigestHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "message_digest_hex: " + err.Error()}
	}
	metaDigest, err := mustHex32(in.MetadataDigestHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "metadata_digest_hex: " + err.Error()}
	}
	userPubkey, err := mustHex32(in.UserPubkeyHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "user_pubkey_hex: " + err.Error()}
	}
	destination, err := mustHex32(in.DestinationHex)
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "invalid_field", "destination_hex: " + err.Error()}
	}
	ikaPK, err := decodeHex(in.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		return nil, &httpError{http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)"}
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindRecovery, in.RuleIndex)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	sessionPDA, _, err := QuorumSessionPDA(s.ProgramID, engine, in.SessionNonce)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	cpiAuth, cpiBump, err := CPIAuthorityPDA(s.ProgramID)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		in.IkaCurve, ikaPK, in.SignatureScheme, msgDigest[:], nil, // recovery: no Ika signing metadata
	)
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	return &quorumDerived{
		dwallet:          dwallet,
		initHash:         initHash,
		engine:           engine,
		rulePDA:          rulePDA,
		sessionPDA:       sessionPDA,
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

// ── /v1/policy/quorum/session/open/{challenge,submit} ────────────────────────

type quorumOpenChallengeRequest struct {
	quorumCommonInputs
	PrimarySlot memberSlotJSON `json:"primary_slot" validate:"required"`
}

type quorumOpenChallengeResponse struct {
	ProgramID              string `json:"program_id"`
	EngineAddress          string `json:"engine_address"`
	RulePDA                string `json:"rule_pda"`
	SessionAddress         string `json:"session_address"`
	MessageApprovalAddress string `json:"message_approval_address"`
	MessageApprovalBump    uint8  `json:"message_approval_bump"`
	OpTag                  string `json:"op_tag"`
	HumanMessage           string `json:"human_message"`
	PreimageHex            string `json:"preimage_hex"`
	ChallengeHex           string `json:"challenge_hex"`
	PrimaryScheme          uint8  `json:"primary_scheme"`
}

func (s *Service) quorumOpenChallenge(w http.ResponseWriter, r *http.Request) {
	var req quorumOpenChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.deriveQuorum(&req.quorumCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}

	in := &QuorumSessionOpenChallengeInput{
		DWallet:             derived.dwallet,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		Amount:              req.Amount,
		Destination:         derived.destination,
		ExpiresAt:           req.ExpiresAt,
		SessionNonce:        req.SessionNonce,
		PrimarySlot:         primarySlot,
	}
	preimage, err := in.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	hash, _ := in.Hash()
	human := HumanMessageQuorumSessionOpen(
		derived.dwallet, req.Amount, derived.destination, derived.msgDigest, derived.metaDigest,
		req.SignatureScheme, req.ExpiresAt,
	)

	httpx.WriteJSON(w, http.StatusOK, quorumOpenChallengeResponse{
		ProgramID:              s.ProgramID.String(),
		EngineAddress:          derived.engine.String(),
		RulePDA:                derived.rulePDA.String(),
		SessionAddress:         derived.sessionPDA.String(),
		MessageApprovalAddress: derived.msgApproval.String(),
		MessageApprovalBump:    derived.msgApprovalBump,
		OpTag:                  string(OpTagQuorumSessionOpen),
		HumanMessage:           string(human),
		PreimageHex:            hex.EncodeToString(preimage),
		ChallengeHex:           hex.EncodeToString(hash[:]),
		PrimaryScheme:          primarySlot[0],
	})
}

type quorumOpenSubmitRequest struct {
	signedSubmitFields
	quorumOpenChallengeRequest
}

func (s *Service) quorumOpenSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req quorumOpenSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	derived, derr := s.deriveQuorum(&req.quorumCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	primarySlot, err := req.PrimarySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "primary_slot: "+err.Error())
		return
	}

	in := &QuorumSessionOpenChallengeInput{
		DWallet:             derived.dwallet,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		Amount:              req.Amount,
		Destination:         derived.destination,
		ExpiresAt:           req.ExpiresAt,
		SessionNonce:        req.SessionNonce,
		PrimarySlot:         primarySlot,
	}
	challenge, err := in.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, err := buildCredentialPrecompile(primarySlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := QuorumSessionOpen(QuorumSessionOpenParams{
		ProgramID:           s.ProgramID,
		Engine:              derived.engine,
		DWallet:             derived.dwallet,
		Payer:               s.GasSponsor.PublicKey(),
		InitAuthorityHash:   derived.initHash,
		RuleIndex:           req.RuleIndex,
		SessionNonce:        req.SessionNonce,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		Amount:              req.Amount,
		Destination:         derived.destination,
		ExpiresAt:           req.ExpiresAt,
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
	extra := fmt.Sprintf(`{"session_nonce":%d,"amount":%d}`, req.SessionNonce, req.Amount)
	s.appendAuditSubmit(r, "quorum.session.open",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── /v1/policy/quorum/session/contribute/{challenge,submit} ──────────────────

type quorumContributeChallengeRequest struct {
	quorumCommonInputs
	MemberSlot memberSlotJSON `json:"member_slot" validate:"required"`
}

type quorumContributeChallengeResponse struct {
	ProgramID      string `json:"program_id"`
	EngineAddress  string `json:"engine_address"`
	SessionAddress string `json:"session_address"`
	OpTag          string `json:"op_tag"`
	HumanMessage   string `json:"human_message"`
	PreimageHex    string `json:"preimage_hex"`
	ChallengeHex   string `json:"challenge_hex"`
	MemberScheme   uint8  `json:"member_scheme"`
}

func (s *Service) quorumContributeChallenge(w http.ResponseWriter, r *http.Request) {
	var req quorumContributeChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.deriveQuorum(&req.quorumCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	memberSlot, err := req.MemberSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "member_slot: "+err.Error())
		return
	}

	in := &QuorumContributeChallengeInput{
		Session:             derived.sessionPDA,
		MemberSlot:          memberSlot,
		DWallet:             derived.dwallet,
		Amount:              req.Amount,
		Destination:         derived.destination,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		ExpiresAt:           req.ExpiresAt,
	}
	preimage, err := in.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	hash, _ := in.Hash()
	human, _ := HumanMessageQuorumContribute(
		derived.sessionPDA, memberSlot, derived.dwallet, req.Amount,
		derived.destination, derived.msgDigest, derived.metaDigest, derived.userPubkey,
		req.SignatureScheme, req.ExpiresAt,
	)

	httpx.WriteJSON(w, http.StatusOK, quorumContributeChallengeResponse{
		ProgramID:      s.ProgramID.String(),
		EngineAddress:  derived.engine.String(),
		SessionAddress: derived.sessionPDA.String(),
		OpTag:          string(OpTagQuorumContribute),
		HumanMessage:   string(human),
		PreimageHex:    hex.EncodeToString(preimage),
		ChallengeHex:   hex.EncodeToString(hash[:]),
		MemberScheme:   memberSlot[0],
	})
}

type quorumContributeSubmitRequest struct {
	signedSubmitFields
	quorumContributeChallengeRequest
	MemberIndex uint8 `json:"member_index"`
}

func (s *Service) quorumContributeSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req quorumContributeSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	derived, derr := s.deriveQuorum(&req.quorumCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	memberSlot, err := req.MemberSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "member_slot: "+err.Error())
		return
	}

	in := &QuorumContributeChallengeInput{
		Session:             derived.sessionPDA,
		MemberSlot:          memberSlot,
		DWallet:             derived.dwallet,
		Amount:              req.Amount,
		Destination:         derived.destination,
		MessageDigest:       derived.msgDigest,
		MetadataDigest:      derived.metaDigest,
		UserPubkey:          derived.userPubkey,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: derived.msgApprovalBump,
		ExpiresAt:           req.ExpiresAt,
	}
	challenge, err := in.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, err := buildCredentialPrecompile(memberSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := QuorumSessionContribute(QuorumSessionContributeParams{
		ProgramID:         s.ProgramID,
		Engine:            derived.engine,
		DWallet:           derived.dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: derived.initHash,
		SessionNonce:      req.SessionNonce,
		MemberIndex:       req.MemberIndex,
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
	extra := fmt.Sprintf(`{"session_nonce":%d,"member_index":%d}`, req.SessionNonce, req.MemberIndex)
	s.appendAuditSubmit(r, "quorum.session.contribute",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── /v1/policy/quorum/session/finalize (permissionless — no signature) ──────

type quorumFinalizeRequest struct {
	quorumCommonInputs
}

func (s *Service) quorumFinalize(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req quorumFinalizeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	derived, derr := s.deriveQuorum(&req.quorumCommonInputs)
	if derr != nil {
		derr.write(w)
		return
	}
	// caller_program must NOT equal program — same pattern as request_signature.
	callerProgram := solana.NewWallet().PublicKey()

	mainIx, err := QuorumSessionFinalize(QuorumSessionFinalizeParams{
		ProgramID:         s.ProgramID,
		Engine:            derived.engine,
		DWallet:           derived.dwallet,
		Coordinator:       IkaCoordinator(),
		MessageApproval:   derived.msgApproval,
		Payer:             s.GasSponsor.PublicKey(),
		CPIAuthority:      derived.cpiAuthority,
		CallerProgram:     callerProgram,
		DWalletProgram:    IkaDwalletProgramID,
		InitAuthorityHash: derived.initHash,
		RuleIndex:         req.RuleIndex,
		SessionNonce:      req.SessionNonce,
		CPIAuthorityBump:  derived.cpiAuthorityBump,
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
	extra := fmt.Sprintf(`{"session_nonce":%d}`, req.SessionNonce)
	s.appendAuditSubmit(r, "quorum.session.finalize",
		derived.engine.String(), derived.dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: derived.engine.String(),
	})
}

// ── /v1/policy/quorum/session/close (recipient signs — Phase2b unsigned-tx) ──
//
// The recipient is the Solana fee payer + sole signer + rent receiver (must
// equal `session.payer_for_close` locked at open time). The gateway can't
// sign as gas sponsor here, so this endpoint behaves as a "prepare":
// it builds the close instruction, fetches a recent blockhash, serialises
// the unsigned transaction, and returns it. The client signs with the
// recipient's keypair off-chain and submits via Solana RPC directly
// (or any tx-relay endpoint).

type quorumCloseRequest struct {
	DwalletAddress    string `json:"dwallet_address"         validate:"required,solana_pubkey"`
	InitAuthorityHash string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	SessionNonce      uint64 `json:"session_nonce"`
	Recipient         string `json:"recipient_address"       validate:"required,solana_pubkey"`
}

func (s *Service) quorumClose(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req quorumCloseRequest
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
	sessionPDA, _, err := QuorumSessionPDA(s.ProgramID, engine, req.SessionNonce)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	closeIx, err := QuorumSessionClose(QuorumSessionCloseParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Recipient:         recipient,
		InitAuthorityHash: initHash,
		SessionNonce:      req.SessionNonce,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	resp, herr := s.buildUnsignedTx(r, recipient, []solana.Instruction{closeIx},
		map[string]any{
			"engine_address":  engine.String(),
			"session_address": sessionPDA.String(),
			"session_nonce":   req.SessionNonce,
		})
	if herr != nil {
		herr.write(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ─── unsigned-tx helper (shared with passkey close) ─────────────────────────

type unsignedTxResponse struct {
	UnsignedTxBase64     string         `json:"unsigned_tx_base64"`
	Blockhash            string         `json:"blockhash"`
	LastValidBlockHeight uint64         `json:"last_valid_block_height"`
	FeePayer             string         `json:"fee_payer"`
	Meta                 map[string]any `json:"meta,omitempty"`
	HowTo                string         `json:"how_to"`
}

// buildUnsignedTx serialises a Solana transaction with `feePayer` as the
// only declared signer (its signature slot is zeroed). The client decodes
// the base64, fills the signature, and submits via any Solana RPC.
//
// The `meta` map is echoed in the response so the client doesn't have to
// re-derive PDAs it already received from the gateway.
func (s *Service) buildUnsignedTx(
	r *http.Request,
	feePayer solana.PublicKey,
	ixs []solana.Instruction,
	meta map[string]any,
) (*unsignedTxResponse, *httpError) {
	if s.RPCClient == nil {
		return nil, &httpError{http.StatusServiceUnavailable, "no_rpc",
			"SOLANA_RPC_URL is not configured"}
	}
	bh, err := s.RPCClient.GetLatestBlockhash(r.Context(), rpc.CommitmentConfirmed)
	if err != nil {
		return nil, &httpError{http.StatusBadGateway, "blockhash_failed", err.Error()}
	}
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(feePayer))
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "build_failed", err.Error()}
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, &httpError{http.StatusInternalServerError, "serialize_failed", err.Error()}
	}
	return &unsignedTxResponse{
		UnsignedTxBase64:     base64.StdEncoding.EncodeToString(raw),
		Blockhash:            bh.Value.Blockhash.String(),
		LastValidBlockHeight: bh.Value.LastValidBlockHeight,
		FeePayer:             feePayer.String(),
		Meta:                 meta,
		HowTo: "Decode `unsigned_tx_base64`, populate the recipient's signature slot, " +
			"and submit via Solana RPC `sendTransaction`. Tx must be submitted before " +
			"`last_valid_block_height` is reached or it'll be rejected as expired.",
	}, nil
}
