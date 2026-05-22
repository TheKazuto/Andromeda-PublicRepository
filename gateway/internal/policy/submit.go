package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// ServiceWithGasSponsor wires the gasponsor (used as fee payer for every
// /submit endpoint). Without it, every /submit returns 503.
func (s *Service) ServiceWithGasSponsor(sp *gasponsor.Signer) *Service {
	s.GasSponsor = sp
	return s
}

// ServiceWithRPC wires the Solana RPC client. Without it, /submit returns 503.
func (s *Service) ServiceWithRPC(c *rpc.Client) *Service {
	s.RPCClient = c
	return s
}

func (s *Service) requireSubmitWiring(w http.ResponseWriter) bool {
	if s.GasSponsor == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "no_gas_sponsor",
			"ANDROMEDA_GAS_SPONSOR_KEYPAIR is not configured")
		return false
	}
	if s.RPCClient == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "no_rpc",
			"SOLANA_RPC_URL is not configured")
		return false
	}
	return true
}

// signedSubmitFields are the fields every /submit endpoint receives from the
// caller after the owner / init_authority has signed the canonical challenge.
type signedSubmitFields struct {
	SignatureBase64        string `json:"signature_base64" validate:"required,base64"`
	WebauthnAuthDataBase64 string `json:"webauthn_auth_data_base64,omitempty" validate:"omitempty,base64"`
	WebauthnCDJBase64      string `json:"webauthn_cdj_base64,omitempty" validate:"omitempty,base64"`
}

func (f signedSubmitFields) decode() (sig []byte, authData []byte, cdj []byte, err error) {
	sig, err = base64.StdEncoding.DecodeString(f.SignatureBase64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signature_base64: %w", err)
	}
	if f.WebauthnAuthDataBase64 != "" {
		authData, err = base64.StdEncoding.DecodeString(f.WebauthnAuthDataBase64)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("webauthn_auth_data_base64: %w", err)
		}
	}
	if f.WebauthnCDJBase64 != "" {
		cdj, err = base64.StdEncoding.DecodeString(f.WebauthnCDJBase64)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("webauthn_cdj_base64: %w", err)
		}
	}
	return sig, authData, cdj, nil
}

// txSignatureResponse — every /submit endpoint returns this on success.
type txSignatureResponse struct {
	TxSignature   string `json:"tx_signature"`
	EngineAddress string `json:"engine_address"`
	// ApprovalSlot is the slot the request_signature tx landed in — pass it as
	// `approvalSlot` to POST /v1/dwallet/sign (the Ika ApprovalProof). Omitted
	// when confirmation timed out; the client then fetches it from the tx
	// signature via any Solana RPC. Only set by the signing submits.
	ApprovalSlot uint64 `json:"approval_slot,omitempty"`
	// PresignSessionIdHex is the presign prefetched during the challenge window
	// (Update 2 Part A), ready for the client to pass straight to
	// POST /v1/dwallet/sign. Omitted when prefetch is off, missed, or N/A —
	// the /sign fallback then allocates a presign inline. Additive: existing
	// submit responses that don't set it serialize exactly as before.
	PresignSessionIdHex string `json:"presign_session_id_hex,omitempty"`
}

// ─── /v1/policy/init/submit ─────────────────────────────────────────────────

type initSubmitRequest struct {
	signedSubmitFields
	DwalletAddress      string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthoritySlot   memberSlotJSON `json:"init_authority_slot" validate:"required"`
	OwnerSlot           memberSlotJSON `json:"owner_slot" validate:"required"`
	DefaultRecoveryHash string         `json:"default_recovery_hash,omitempty" validate:"omitempty,hex_len=32"`
}

func (s *Service) initSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req initSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initSlot, err := req.InitAuthoritySlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "init_authority_slot: "+err.Error())
		return
	}
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}
	initHash := InitAuthorityHashFromSlot(initSlot)
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	var recoveryHash [32]byte
	present := uint8(0)
	if req.DefaultRecoveryHash != "" {
		recoveryHash, err = mustHex32(req.DefaultRecoveryHash)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
			return
		}
		present = 1
	}
	if present == 1 {
		httpx.WriteError(w, http.StatusNotImplemented, "default_recovery_not_yet",
			"default_recovery_present=1 is F9 scope")
		return
	}

	_, challenge := initChallengePreimageAndHash(dwallet, initSlot, ownerSlot, present, recoveryHash)

	precompile, err := buildCredentialPrecompile(initSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := InitEngine(InitEngineParams{
		ProgramID:              s.ProgramID,
		DWallet:                dwallet,
		Engine:                 engine,
		Payer:                  s.GasSponsor.PublicKey(),
		InitAuthoritySlot:      initSlot,
		InitAuthorityHash:      initHash,
		OwnerSlot:              ownerSlot,
		DefaultRecoveryPresent: present,
		DefaultRecoveryHash:    recoveryHash,
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
	// F10: audit-log the landed tx. No-op when audit isn't wired.
	s.appendAuditSubmit(r, "init", engine.String(), dwallet.String(), sigOut.String(), "")
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// ─── /v1/policy/rules/add/submit ────────────────────────────────────────────

type addRuleSubmitRequest struct {
	signedSubmitFields
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	RuleIndex         uint8          `json:"rule_index" validate:"max=15"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	AppliesTo         uint8          `json:"applies_to" validate:"required,min=1,max=7"`
	// Oracle (rule_kind=4) + SpendingUsd (rule_kind=9); divided forms (see addRuleRequest).
	FreshnessSecondsDiv16 uint8 `json:"freshness_seconds_div16,omitempty"`
	MinConfidenceBpsDiv4  uint8 `json:"min_confidence_bps_div4,omitempty"`
	// SpendingUsd-only (rule_kind=9). USD ceilings, canonical 1e8.
	MaxPerTxUsd   uint64 `json:"max_per_tx_usd,omitempty"`
	MaxPerDayUsd  uint64 `json:"max_per_day_usd,omitempty"`
	MaxPerWeekUsd uint64 `json:"max_per_week_usd,omitempty"`
}

func (s *Service) addRuleSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req addRuleSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	switch RuleKind(req.RuleKind) {
	case KindAllowlist:
		s.addRuleAllowlistSubmit(w, r, req)
	case KindOracle:
		s.addRuleOracleSubmit(w, r, req)
	case KindSpendingUsd:
		s.addRuleSpendingUsdSubmit(w, r, req)
	default:
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"rule_kind must be 1 (Allowlist), 4 (Oracle) or 9 (SpendingUsd)")
	}
}

func (s *Service) addRuleAllowlistSubmit(w http.ResponseWriter, r *http.Request, req addRuleSubmitRequest) {
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	// Reconstruct the challenge bytes (same logic as addRuleAllowlistChallenge).
	emptyDest := make([]byte, 1024)
	configHash, err := AllowlistConfigHash(req.AppliesTo, 0, emptyDest)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	human := HumanMessageAllowlistPause(engine, dwallet)
	gen := uint32(1) // first add — generation 0 → 1
	var genLE [4]byte
	binaryLittleEndianPutUint32Local(genLE[:], gen)
	ch := &AdminChallengeInput{
		OpTag:          OpAddAllowlist,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindAllowlist),
		RuleIndex:      req.RuleIndex,
		RuleGeneration: gen,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{{req.AppliesTo}, genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := AddRuleAllowlist(AddRuleAllowlistParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         req.RuleIndex,
		AppliesTo:         req.AppliesTo,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d,"applies_to":%d}`,
		req.RuleKind, req.RuleIndex, req.AppliesTo)
	s.appendAuditSubmit(r, "rule.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// addRuleOracleSubmit lands [precompile + add_rule_oracle (disc 13)]. The rule
// is created with feeds_count=0; feeds are appended afterwards via the items/add
// (disc 122) endpoint. First add bumps the rule generation 0 → 1.
func (s *Service) addRuleOracleSubmit(w http.ResponseWriter, r *http.Request, req addRuleSubmitRequest) {
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	emptyFeeds := make([]byte, MaxOracleFeeds*OracleFeedBytes)
	configHash, err := OracleConfigHash(req.AppliesTo, 0, req.FreshnessSecondsDiv16, req.MinConfidenceBpsDiv4, emptyFeeds)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	human := HumanMessageAllowlistPause(engine, dwallet)
	gen := uint32(1) // first add — generation 0 → 1
	var genLE [4]byte
	binaryLittleEndianPutUint32Local(genLE[:], gen)
	ch := &AdminChallengeInput{
		OpTag:          OpAddOracle,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindOracle),
		RuleIndex:      req.RuleIndex,
		RuleGeneration: gen,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{{req.AppliesTo}, {req.FreshnessSecondsDiv16}, {req.MinConfidenceBpsDiv4}, genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := AddRuleOracle(AddRuleOracleParams{
		ProgramID:             s.ProgramID,
		Engine:                engine,
		DWallet:               dwallet,
		Payer:                 s.GasSponsor.PublicKey(),
		InitAuthorityHash:     initHash,
		ExpectedNonce:         req.ExpectedNonce,
		RuleIndex:             req.RuleIndex,
		AppliesTo:             req.AppliesTo,
		FreshnessSecondsDiv16: req.FreshnessSecondsDiv16,
		MinConfidenceBpsDiv4:  req.MinConfidenceBpsDiv4,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d,"applies_to":%d}`,
		req.RuleKind, req.RuleIndex, req.AppliesTo)
	s.appendAuditSubmit(r, "rule.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// ─── /v1/policy/rules/{ruleIndex}/items/add/submit ──────────────────────────

type itemsAddSubmitRequest struct {
	signedSubmitFields
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	RuleGeneration    uint32         `json:"rule_generation" validate:"required,min=1"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	// Allowlist item (rule_kind=1).
	DestinationHex string `json:"destination_hex,omitempty" validate:"omitempty,hex_len=32"`
	// Oracle feed (rule_kind=4) — see itemsAddRequest.
	FeedAccount string `json:"feed_account,omitempty" validate:"omitempty,solana_pubkey"`
	FeedOwner   string `json:"feed_owner,omitempty" validate:"omitempty,solana_pubkey"`
	MinQ64      int64  `json:"min_q64,omitempty"`
	MaxQ64      int64  `json:"max_q64,omitempty"`
	// SpendingUsd feed (rule_kind=9). FeedAccount (reused) is the FeedCache PDA.
	Decimals uint8 `json:"decimals,omitempty" validate:"max=24"`
}

func (s *Service) itemsAddSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	ruleIndexStr := chi.URLParam(r, "ruleIndex")
	ruleIndex, err := strconv.Atoi(ruleIndexStr)
	if err != nil || ruleIndex < 0 || ruleIndex >= MaxRules {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_rule_index", "ruleIndex must be 0..15")
		return
	}
	var req itemsAddSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	switch RuleKind(req.RuleKind) {
	case KindAllowlist:
		s.itemsAddAllowlistSubmit(w, r, req, uint8(ruleIndex))
	case KindOracle:
		s.itemsAddOracleSubmit(w, r, req, uint8(ruleIndex))
	case KindSpendingUsd:
		s.itemsAddSpendingUsdSubmit(w, r, req, uint8(ruleIndex))
	default:
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"rule_kind must be 1 (Allowlist), 4 (Oracle) or 9 (SpendingUsd)")
	}
}

func (s *Service) itemsAddAllowlistSubmit(w http.ResponseWriter, r *http.Request, req itemsAddSubmitRequest, ruleIndex uint8) {
	if req.DestinationHex == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "destination_hex is required for rule_kind=1")
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	dest, _ := mustHex32(req.DestinationHex)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	human := HumanMessageAllowlistAddDestination(dest, engine, dwallet)
	var genLE [4]byte
	binaryLittleEndianPutUint32Local(genLE[:], req.RuleGeneration)
	ch := &AdminChallengeInput{
		OpTag:          OpAllowlistAddDest,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindAllowlist),
		RuleIndex:      ruleIndex,
		RuleGeneration: req.RuleGeneration,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     [32]byte{},
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{dest[:], genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := UpdateRuleAllowlistAddDestination(UpdateRuleAllowlistAddDestinationParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         ruleIndex,
		Destination:       dest,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d}`, req.RuleKind, ruleIndex)
	s.appendAuditSubmit(r, "rule.items.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// itemsAddOracleSubmit lands [precompile + update_rule_oracle_add_feed (disc
// 122)]. rule_generation must be the post-update value (current + 1).
func (s *Service) itemsAddOracleSubmit(w http.ResponseWriter, r *http.Request, req itemsAddSubmitRequest, ruleIndex uint8) {
	feedAccount, feedOwner, ok := decodeOracleFeed(w, req.FeedAccount, req.FeedOwner, req.MinQ64, req.MaxQ64)
	if !ok {
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	human := HumanMessageOracleAddFeed(feedAccount, feedOwner, req.MinQ64, req.MaxQ64, engine, dwallet)
	var genLE [4]byte
	binaryLittleEndianPutUint32Local(genLE[:], req.RuleGeneration)
	minLE, maxLE := int64LE(req.MinQ64), int64LE(req.MaxQ64)
	fa, fo := feedAccount.Bytes(), feedOwner.Bytes()
	ch := &AdminChallengeInput{
		OpTag:          OpOracleAddFeed,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindOracle),
		RuleIndex:      ruleIndex,
		RuleGeneration: req.RuleGeneration,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     [32]byte{},
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{fa, fo, minLE[:], maxLE[:], genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	var feedAccountArr, feedOwnerArr [32]byte
	copy(feedAccountArr[:], fa)
	copy(feedOwnerArr[:], fo)
	mainIx, err := UpdateRuleOracleAddFeed(UpdateRuleOracleAddFeedParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         ruleIndex,
		FeedAccount:       feedAccountArr,
		FeedOwner:         feedOwnerArr,
		MinQ64:            req.MinQ64,
		MaxQ64:            req.MaxQ64,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d}`, req.RuleKind, ruleIndex)
	s.appendAuditSubmit(r, "rule.items.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// ─── /v1/policy/request-signature/submit ────────────────────────────────────
//
// F2.6b limitation: this endpoint is intentionally **not yet** wired through
// `SignAndSend` because it requires the Ika `message_approval_bump` and
// `cpi_authority_bump` to be resolved against a real Ika dWallet account
// (current `gateway/internal/policies/` has the helper `MessageApprovalPDA`
// we will reuse in F2.6c). Returns 501 with a pointer.

type requestSignatureSubmitRequest struct {
	DwalletAddress    string `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	MessageDigestHex  string `json:"message_digest_hex" validate:"required,hex_len=32"`
	MetadataDigestHex string `json:"metadata_digest_hex" validate:"required,hex_len=32"`
	UserPubkeyHex     string `json:"user_pubkey_hex" validate:"required,hex_len=32"`
	SignatureScheme   uint16 `json:"signature_scheme" validate:"max=6"` // DWalletSignatureScheme 0..6 (5=EddsaSha512 Solana/Sui, 6=SchnorrkelMerlin)
	DestinationHex    string `json:"destination_hex" validate:"required,hex_len=32"`
	RulesGeneration   uint32 `json:"rules_generation_seen"`
	// F8a: client passes one sub-PDA per active rule slot, in ascending slot
	// order. If the engine has zero active rules, pass an empty array. The
	// gateway is responsible for resolving these from the on-chain
	// `PolicyEngine.rules_flat` index (helper PDA derivation lives in
	// codecs.go).
	RulePDAs []string `json:"rule_pdas,omitempty" validate:"omitempty,dive,solana_pubkey"`
	// RuleAuxAccounts carries auxiliary read-only accounts consumed after each
	// sub-PDA, indexed parallel to RulePDAs. KIND_ORACLE rules pass one
	// FeedCache PDA per feed (`[b"feed_cache", feed_id]` under the Pyth adapter
	// program) in feeds_flat order; other kinds pass an empty inner array.
	// Optional — when absent, behaves exactly as before (no aux accounts).
	RuleAuxAccounts [][]string `json:"rule_aux_accounts,omitempty"`
	// AutoResolveAccounts lets the gateway read the on-chain engine + rule
	// sub-PDAs and build the trailing accounts itself (sub-PDA per active slot
	// + oracle FeedCache aux). When true, `rule_pdas` / `rule_aux_accounts` are
	// ignored. Not supported when an active passkey rule applies to PATH_NORMAL
	// (its aux is a runtime WebAuthn artifact) — pass accounts manually then.
	AutoResolveAccounts bool   `json:"auto_resolve_accounts,omitempty"`
	IkaCurve            uint16 `json:"ika_curve" validate:"max=2"`
	IkaDWalletPubkey    string `json:"ika_dwallet_pubkey_hex" validate:"required"`
	// Update 3 (ABI V2): asset amount (base units) + index in the active
	// KIND_SPENDING_USD allowlist. Bound into the metadata digest the client
	// obtained from /request-signature/challenge. Default 0/0 when no spending
	// rule is active. `asset_index` is capped at MaxSpendingUsdFeeds-1.
	Amount     uint64 `json:"amount,omitempty"`
	AssetIndex uint8  `json:"asset_index,omitempty" validate:"max=15"`
}

func (s *Service) requestSignatureSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req requestSignatureSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	mainIx, engine, dwallet, auxCaches, ok := s.buildRequestSignatureIx(r.Context(), w, &req, s.GasSponsor.PublicKey())
	if !ok {
		return
	}

	// Refresh-on-sign: prepend a refresh_feed for each sponsored FeedCache this
	// tx reads, so the price is fresh at the signing moment. Best-effort and
	// observed — on a refresher error we log and proceed; the on-chain freshness
	// check (OracleStale) is the authoritative backstop, and the managed crank
	// may have refreshed already.
	ixs := []solana.Instruction{mainIx}
	if s.oracleRefresher != nil && len(auxCaches) > 0 {
		refreshIxs, rerr := s.oracleRefresher.RefreshIxs(r.Context(), auxCaches)
		if rerr != nil {
			slog.Warn("refresh-on-sign skipped", "engine", engine.String(), "err", rerr)
		} else if len(refreshIxs) > 0 {
			ixs = append(refreshIxs, mainIx)
		}
	}

	sigOut, err := s.GasSponsor.SignAndSend(r.Context(), ixs)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}
	extra := fmt.Sprintf(`{"signature_scheme":%d,"rules_generation":%d}`,
		req.SignatureScheme, req.RulesGeneration)
	s.appendAuditSubmit(r, "request-signature", engine.String(), dwallet.String(), sigOut.String(), extra)
	// Update 2 Part A: hand the client the presign prefetched at challenge time
	// (keyed by the same metadata digest), so /sign skips the inline allocation.
	// approval_slot is the slot this tx landed in — needed by /v1/dwallet/sign.
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:         sigOut.String(),
		EngineAddress:       engine.String(),
		ApprovalSlot:        s.confirmApprovalSlot(r.Context(), sigOut),
		PresignSessionIdHex: s.harvestPresign(r, req.MetadataDigestHex),
	})
}

// approvalConfirmTimeout bounds the best-effort wait to learn the slot the
// request_signature tx landed in (for the Ika ApprovalProof).
const approvalConfirmTimeout = 30 * time.Second

// confirmApprovalSlot best-effort resolves the slot a just-sent signing tx
// landed in, so the submit can hand it back for POST /v1/dwallet/sign. Returns
// 0 when it can't confirm in time — the client then fetches the slot from the
// returned tx signature via any Solana RPC.
func (s *Service) confirmApprovalSlot(ctx context.Context, sig solana.Signature) uint64 {
	if s.GasSponsor == nil {
		return 0
	}
	slot, err := s.GasSponsor.ConfirmSlot(ctx, sig, approvalConfirmTimeout)
	if err != nil {
		slog.Warn("approval slot not confirmed in time", "sig", sig.String(), "err", err)
		return 0
	}
	return slot
}

// buildError carries an HTTP-shaped failure from the pure assembler so the
// HTTP wrappers can render it, while the programmatic firer (FireRequestSignature)
// can turn it into a plain error.
type buildError struct {
	status int
	code   string
	msg    string
}

func (e *buildError) Error() string { return e.msg }

// buildRequestSignatureIx parses a request_signature request, resolves the
// trailing accounts, and builds the instruction with the given payer. Shared by
// submit (gas sponsor payer, then send) and build (client payer). On any
// validation error it writes the HTTP response and returns ok=false. Thin HTTP
// wrapper around assembleRequestSignatureIx.
func (s *Service) buildRequestSignatureIx(
	ctx context.Context, w http.ResponseWriter, req *requestSignatureSubmitRequest, payer solana.PublicKey,
) (solana.Instruction, solana.PublicKey, solana.PublicKey, []solana.PublicKey, bool) {
	var zero solana.PublicKey
	ix, engine, dwallet, auxCaches, berr := s.assembleRequestSignatureIx(ctx, req, payer)
	if berr != nil {
		httpx.WriteError(w, berr.status, berr.code, berr.msg)
		return nil, zero, zero, nil, false
	}
	return ix, engine, dwallet, auxCaches, true
}

// assembleRequestSignatureIx is the pure (no http.ResponseWriter) core: it
// derives every PDA, resolves the trailing accounts, and builds the
// request_signature instruction with `payer`. Returns a *buildError on any
// validation/derivation failure so both the HTTP wrappers and the programmatic
// firer can reuse the exact same auditable logic.
func (s *Service) assembleRequestSignatureIx(
	ctx context.Context, req *requestSignatureSubmitRequest, payer solana.PublicKey,
) (solana.Instruction, solana.PublicKey, solana.PublicKey, []solana.PublicKey, *buildError) {
	var zero solana.PublicKey
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	msgDigest, _ := mustHex32(req.MessageDigestHex)
	metaDigest, _ := mustHex32(req.MetadataDigestHex)
	userPK, _ := mustHex32(req.UserPubkeyHex)
	dest, _ := mustHex32(req.DestinationHex)

	ikaPK, err := decodeHex(req.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		return nil, zero, zero, nil, &buildError{http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)"}
	}

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return nil, zero, zero, nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	cpiAuth, cpiBump, err := CPIAuthorityPDA(s.ProgramID)
	if err != nil {
		return nil, zero, zero, nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:],
	)
	if err != nil {
		return nil, zero, zero, nil, &buildError{http.StatusInternalServerError, "pda_derivation_failed", err.Error()}
	}

	// One sub-PDA per active rule slot, ascending. Empty is valid (zero rules).
	rulePDAs := make([]solana.PublicKey, 0, len(req.RulePDAs))
	for i, str := range req.RulePDAs {
		pk, err := solana.PublicKeyFromBase58(str)
		if err != nil {
			return nil, zero, zero, nil, &buildError{http.StatusBadRequest, "invalid_field",
				fmt.Sprintf("rule_pdas[%d]: %v", i, err)}
		}
		rulePDAs = append(rulePDAs, pk)
	}

	if len(req.RuleAuxAccounts) > len(rulePDAs) {
		return nil, zero, zero, nil, &buildError{http.StatusBadRequest, "invalid_field",
			"rule_aux_accounts has more groups than rule_pdas"}
	}
	ruleAux := make([][]solana.PublicKey, len(req.RuleAuxAccounts))
	for i, group := range req.RuleAuxAccounts {
		for j, a := range group {
			pk, err := solana.PublicKeyFromBase58(a)
			if err != nil {
				return nil, zero, zero, nil, &buildError{http.StatusBadRequest, "invalid_field",
					fmt.Sprintf("rule_aux_accounts[%d][%d]: %v", i, j, err)}
			}
			ruleAux[i] = append(ruleAux[i], pk)
		}
	}

	if req.AutoResolveAccounts {
		if s.RPCClient == nil {
			return nil, zero, zero, nil, &buildError{http.StatusServiceUnavailable, "no_rpc",
				"auto_resolve_accounts requires SOLANA_RPC_URL"}
		}
		resolvedPDAs, resolvedAux, rerr := s.resolveTrailingAccounts(ctx, engine, req.AssetIndex)
		if rerr != nil {
			return nil, zero, zero, nil, &buildError{http.StatusBadGateway, "resolve_failed", rerr.Error()}
		}
		rulePDAs = resolvedPDAs
		ruleAux = resolvedAux
	}

	// `caller_program` must NOT equal `program` in the account list (Quasar/SVM
	// rejects AccountBorrowFailed when duplicated). Unique placeholder; the Ika
	// mock ignores it and the real Ika does not validate it semantically.
	callerProgram := solana.NewWallet().PublicKey()

	mainIx, err := RequestSignature(RequestSignatureParams{
		ProgramID:           s.ProgramID,
		Engine:              engine,
		DWallet:             dwallet,
		Coordinator:         IkaCoordinator(), // Ika DWalletCoordinator PDA (approve_message CPI)
		MessageApproval:     msgApproval,
		Payer:               payer,
		CPIAuthority:        cpiAuth,
		CallerProgram:       callerProgram,
		DWalletProgram:      IkaDwalletProgramID,
		RulePDAs:            rulePDAs,
		RuleAux:             ruleAux,
		InitAuthorityHash:   initHash,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPK,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: msgApprovalBump,
		CPIAuthorityBump:    cpiBump,
		Destination:         dest,
		RulesGenerationSeen: req.RulesGeneration,
		Amount:              req.Amount,
		AssetIndex:          req.AssetIndex,
	})
	if err != nil {
		return nil, zero, zero, nil, &buildError{http.StatusInternalServerError, "build_failed", err.Error()}
	}
	// Flatten the resolved trailing aux accounts (oracle FeedCache PDAs and,
	// for other kinds, runtime aux). Returned so the gas-sponsored submit path
	// can prepend a refresh_feed for each sponsored feed; the refresher filters
	// these to known catalog feeds, so non-feed aux are harmlessly ignored.
	var auxCaches []solana.PublicKey
	for _, group := range ruleAux {
		auxCaches = append(auxCaches, group...)
	}
	return mainIx, engine, dwallet, auxCaches, nil
}

// FireRequestSignature builds and lands a request_signature transaction from a
// stored payload (same shape as POST /v1/policy/request-signature/submit),
// gas-sponsored and with refresh-on-sign prepended. It is the programmatic
// counterpart of requestSignatureSubmit used by the managed oracle monitor
// (F7.5): no owner precompile is needed because request_signature is authorised
// entirely by the on-chain rules (the dispatch re-validates the oracle band,
// destination allowlist, etc.). A wrong/compromised monitor therefore can only
// release a pre-committed message when the on-chain rule would already pass.
//
// Implements oraclemonitor.Firer. Returns the landed Solana tx signature.
func (s *Service) FireRequestSignature(ctx context.Context, payload json.RawMessage) (string, error) {
	if s.GasSponsor == nil {
		return "", fmt.Errorf("gas sponsor not configured")
	}
	if s.RPCClient == nil {
		return "", fmt.Errorf("rpc not configured")
	}
	req, err := decodeRequestSignaturePayload(payload)
	if err != nil {
		return "", err
	}

	mainIx, _, _, auxCaches, berr := s.assembleRequestSignatureIx(ctx, &req, s.GasSponsor.PublicKey())
	if berr != nil {
		return "", fmt.Errorf("build request_signature: %s", berr.msg)
	}

	// Refresh-on-sign: prepend a refresh_feed per sponsored FeedCache the tx
	// reads, so the price is fresh at the signing moment (best-effort; the
	// on-chain OracleStale check is the authoritative backstop).
	ixs := []solana.Instruction{mainIx}
	if s.oracleRefresher != nil && len(auxCaches) > 0 {
		if refreshIxs, rerr := s.oracleRefresher.RefreshIxs(ctx, auxCaches); rerr == nil && len(refreshIxs) > 0 {
			ixs = append(refreshIxs, mainIx)
		}
	}

	sigOut, err := s.GasSponsor.SignAndSend(ctx, ixs)
	if err != nil {
		return "", fmt.Errorf("send request_signature: %w", err)
	}
	return sigOut.String(), nil
}

// ValidateRequestSignaturePayload decodes + validates a stored request_signature
// payload with the SAME schema the HTTP submit path enforces, without sending
// anything. The oracle monitor calls this at arm time so a malformed payload is
// rejected when the dev arms the trigger (immediate feedback) instead of only
// failing later at fire time. Implements oraclemonitor.Firer.
func (s *Service) ValidateRequestSignaturePayload(payload json.RawMessage) error {
	_, err := decodeRequestSignaturePayload(payload)
	return err
}

// decodeRequestSignaturePayload unmarshals + struct-validates a stored payload.
// Shared by ValidateRequestSignaturePayload (arm time) and FireRequestSignature
// (fire time) so the two never drift.
func decodeRequestSignaturePayload(payload json.RawMessage) (requestSignatureSubmitRequest, error) {
	var req requestSignatureSubmitRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return req, fmt.Errorf("decode request_signature payload: %w", err)
	}
	if err := httpx.V().Struct(&req); err != nil {
		return req, fmt.Errorf("invalid request_signature payload: %w", err)
	}
	return req, nil
}

// ─── /v1/policy/request-signature/build (on-demand, client-pays) ────────────

type requestSignatureBuildRequest struct {
	requestSignatureSubmitRequest
	// Payer is the client/keeper key that will pay + sign the assembled tx.
	Payer string `json:"payer" validate:"required,solana_pubkey"`
}

type instructionAcctJSON struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

type instructionJSON struct {
	ProgramID  string                `json:"program_id"`
	Accounts   []instructionAcctJSON `json:"accounts"`
	DataBase64 string                `json:"data_base64"`
}

type requestSignatureBuildResponse struct {
	EngineAddress string          `json:"engine_address"`
	Instruction   instructionJSON `json:"request_signature_instruction"`
}

// requestSignatureBuild returns the request_signature instruction (with a
// client-chosen payer) so a keeper can assemble an on-demand transaction
// client-side: [post_update (Pyth SDK) + refresh_feed + this instruction],
// then pay, sign and submit it. The gateway neither signs nor sends, so it
// bears no cost and the gas-sponsor key is never exposed to a client tx.
func (s *Service) requestSignatureBuild(w http.ResponseWriter, r *http.Request) {
	var req requestSignatureBuildRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	payer, err := solana.PublicKeyFromBase58(req.Payer)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "payer must be base58")
		return
	}
	mainIx, engine, _, _, ok := s.buildRequestSignatureIx(r.Context(), w, &req.requestSignatureSubmitRequest, payer)
	if !ok {
		return
	}
	ixJSON, err := serializeInstruction(mainIx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "serialize_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, requestSignatureBuildResponse{
		EngineAddress: engine.String(),
		Instruction:   ixJSON,
	})
}

func serializeInstruction(ix solana.Instruction) (instructionJSON, error) {
	data, err := ix.Data()
	if err != nil {
		return instructionJSON{}, err
	}
	accts := ix.Accounts()
	out := instructionJSON{
		ProgramID:  ix.ProgramID().String(),
		Accounts:   make([]instructionAcctJSON, len(accts)),
		DataBase64: base64.StdEncoding.EncodeToString(data),
	}
	for i, a := range accts {
		out.Accounts[i] = instructionAcctJSON{
			Pubkey:     a.PublicKey.String(),
			IsSigner:   a.IsSigner,
			IsWritable: a.IsWritable,
		}
	}
	return out, nil
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex length must be even")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b [2]byte
		b[0] = s[i*2]
		b[1] = s[i*2+1]
		var hi, lo byte
		switch {
		case b[0] >= '0' && b[0] <= '9':
			hi = b[0] - '0'
		case b[0] >= 'a' && b[0] <= 'f':
			hi = b[0] - 'a' + 10
		case b[0] >= 'A' && b[0] <= 'F':
			hi = b[0] - 'A' + 10
		default:
			return nil, fmt.Errorf("invalid hex char %q", b[0])
		}
		switch {
		case b[1] >= '0' && b[1] <= '9':
			lo = b[1] - '0'
		case b[1] >= 'a' && b[1] <= 'f':
			lo = b[1] - 'a' + 10
		case b[1] >= 'A' && b[1] <= 'F':
			lo = b[1] - 'A' + 10
		default:
			return nil, fmt.Errorf("invalid hex char %q", b[1])
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// ─── precompile helper ──────────────────────────────────────────────────────

// buildCredentialPrecompile is a thin wrapper around
// `auth.BuildCredentialPrecompile` that adapts the policy package's slot
// type to the auth package's expectation.
func buildCredentialPrecompile(
	slot [MemberSlotLen]byte,
	challenge [32]byte,
	signature, webauthnAuthData, webauthnCDJ []byte,
) (solana.Instruction, error) {
	var authSlot [auth.MemberSlotLen]byte
	copy(authSlot[:], slot[:])
	ix, err := auth.BuildCredentialPrecompile(authSlot, challenge, signature, webauthnAuthData, webauthnCDJ)
	if err != nil {
		return nil, err
	}
	return ix, nil
}

// Avoid an unused-import warning when context is referenced only by the
// closures above.
var _ = context.Background
