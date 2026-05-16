package policy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"

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
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=8"`
	RuleIndex         uint8          `json:"rule_index" validate:"max=15"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	AppliesTo         uint8          `json:"applies_to" validate:"required,min=1,max=7"`
}

func (s *Service) addRuleSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req addRuleSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	if RuleKind(req.RuleKind) != KindAllowlist {
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"F2.6b supports rule_kind=1 (Allowlist) only")
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

	// Reconstruct the challenge bytes (same logic as addRuleChallenge handler).
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

// ─── /v1/policy/rules/{ruleIndex}/items/add/submit ──────────────────────────

type itemsAddSubmitRequest struct {
	signedSubmitFields
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=8"`
	RuleGeneration    uint32         `json:"rule_generation" validate:"required,min=1"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	DestinationHex    string         `json:"destination_hex" validate:"required,hex_len=32"`
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
	if RuleKind(req.RuleKind) != KindAllowlist {
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"F2.6b supports rule_kind=1 (Allowlist) only")
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
		RuleIndex:      uint8(ruleIndex),
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
		RuleIndex:         uint8(ruleIndex),
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
	SignatureScheme   uint16 `json:"signature_scheme" validate:"max=4"`
	DestinationHex    string `json:"destination_hex" validate:"required,hex_len=32"`
	RulesGeneration   uint32 `json:"rules_generation_seen"`
	// F8a: client passes one sub-PDA per active rule slot, in ascending slot
	// order. If the engine has zero active rules, pass an empty array. The
	// gateway is responsible for resolving these from the on-chain
	// `PolicyEngine.rules_flat` index (helper PDA derivation lives in
	// codecs.go).
	RulePDAs         []string `json:"rule_pdas,omitempty" validate:"omitempty,dive,solana_pubkey"`
	IkaCurve         uint16   `json:"ika_curve" validate:"max=2"`
	IkaDWalletPubkey string   `json:"ika_dwallet_pubkey_hex" validate:"required"`
}

func (s *Service) requestSignatureSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	var req requestSignatureSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	msgDigest, _ := mustHex32(req.MessageDigestHex)
	metaDigest, _ := mustHex32(req.MetadataDigestHex)
	userPK, _ := mustHex32(req.UserPubkeyHex)
	dest, _ := mustHex32(req.DestinationHex)

	ikaPK, err := decodeHex(req.IkaDWalletPubkey)
	if err != nil || len(ikaPK) == 0 || len(ikaPK) > 96 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"ika_dwallet_pubkey_hex must be 1..96-byte hex (curve pubkey)")
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
	msgApproval, msgApprovalBump, err := MessageApprovalPDA(
		req.IkaCurve, ikaPK, req.SignatureScheme, msgDigest[:], metaDigest[:],
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	// F8a: parse rule PDAs from request — one per active slot, ascending.
	// Empty array is valid when the engine has zero active rules.
	rulePDAs := make([]solana.PublicKey, 0, len(req.RulePDAs))
	for i, s := range req.RulePDAs {
		pk, err := solana.PublicKeyFromBase58(s)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
				fmt.Sprintf("rule_pdas[%d]: %v", i, err))
			return
		}
		rulePDAs = append(rulePDAs, pk)
	}

	// `caller_program` must NOT equal `program` in the account list (Quasar /
	// SVM rejects with AccountBorrowFailed when duplicated). We pass a unique
	// placeholder — the on-chain Ika mock ignores it; the real Ika does not
	// validate it semantically either, but this is flagged for F9 review.
	callerProgram := solana.NewWallet().PublicKey()

	mainIx, err := RequestSignature(RequestSignatureParams{
		ProgramID:           s.ProgramID,
		Engine:              engine,
		DWallet:             dwallet,
		Coordinator:         dwallet, // F2.6c placeholder — real coordinator lookup is F9
		MessageApproval:     msgApproval,
		Payer:               s.GasSponsor.PublicKey(),
		CPIAuthority:        cpiAuth,
		CallerProgram:       callerProgram,
		DWalletProgram:      IkaDwalletProgramID,
		RulePDAs:            rulePDAs,
		InitAuthorityHash:   initHash,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPK,
		SignatureScheme:     req.SignatureScheme,
		MessageApprovalBump: msgApprovalBump,
		CPIAuthorityBump:    cpiBump,
		Destination:         dest,
		RulesGenerationSeen: req.RulesGeneration,
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
	extra := fmt.Sprintf(`{"signature_scheme":%d,"rules_generation":%d}`,
		req.SignatureScheme, req.RulesGeneration)
	s.appendAuditSubmit(r, "request-signature", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
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
