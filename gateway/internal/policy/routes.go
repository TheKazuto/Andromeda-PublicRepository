package policy

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
	"github.com/shinkalabs/andromeda-gateway/internal/risk"
)

// Service wires the PolicyEngine v3 REST surface.
//
// F2.6  entrega os `/challenge` endpoints (computa o challenge canônico que
//
//	o owner assina off-chain).
//
// F2.6b entrega os `/submit` endpoints exceto `request-signature/submit`
//
//	(depende de MessageApproval PDA + CPI authority bump — F2.6c).
//
// F10 hardening adiciona o wiring opcional de `AuditRecorder` para
// registrar cada submit bem-sucedido na cadeia ed25519 do tenant.
type Service struct {
	// ProgramID is the deployed PolicyEngine program (defaults to
	// `ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL` if zero).
	ProgramID solana.PublicKey

	// GasSponsor is the gateway-controlled keypair that pays Solana fees.
	// Required for /submit endpoints; without it those return 503.
	GasSponsor *gasponsor.Signer

	// RPCClient is the Solana RPC used to fetch blockhashes / submit txs.
	// Required for /submit endpoints; without it those return 503.
	RPCClient *rpc.Client

	// F10: optional audit log wiring. When both fields are set, each
	// successful /submit records a signed event to the tenant's audit
	// chain via Vault Transit. Failures never propagate to the HTTP
	// response — the on-chain tx already landed.
	auditAppender AuditAppender
	resolveAPIKey func(*http.Request) (string, error)

	// RT2: optional tenant resolver for risk routes. Resolves the API key ID
	// from the request context. Used by /v1/policy/risk/* CRUD endpoints
	// to determine the tenant scope. Wired via WithTenantResolver.
	tenantResolver func(*http.Request) (string, error)

	// oracleRefresher (optional) prepends a refresh_feed to the gas-sponsored
	// request_signature for each sponsored FeedCache the tx reads, so the price
	// is fresh at signing time. Wired in main with the Pyth adapter program id.
	oracleRefresher OracleRefresher

	// Async presign prefetch (Update 2 Part A). All optional; when any is nil
	// the feature is off and signing behaves exactly as before. Wired via
	// WithPresignPrefetch / WithPresignMetrics.
	presignDispatcher PresignDispatcher
	presignCache      PresignCache
	presignMetrics    PresignMetrics
	resolveTenant     func(*http.Request) string
	presignTTL        time.Duration
	// presignMaxPerMinute caps sponsored presign dispatches per tenant per
	// minute (F1 C). 0 disables the cap.
	presignMaxPerMinute int
	// presignSem bounds the number of in-flight background prefetch goroutines
	// so a burst of challenges can't pile up unbounded goroutines (each lives
	// up to presignDispatchTimeout). Non-blocking: when full, the prefetch is
	// dropped (best-effort) and /sign allocates the presign inline.
	presignSem chan struct{}

	// RT2: optional risk scoring service for transaction risk gating.
	// When set, evaluates destination risk before signing. Wired via
	// WithRiskService in main.
	riskService RiskService

	// RT2: optional config service for managing risk policies.
	// Wired via WithRiskConfigService in main.
	riskConfigService RiskConfigService

	// RT2: optional HTTP client for internal ika-backend simulation endpoint.
	// Used to verify digest matches before risk evaluation. Wired via
	// WithIkaSimulateClient in main with circuit breaker.
	ikaSimulateClient IkaSimulateClient
}

// OracleRefresher builds refresh_feed instructions to prepend to a
// gas-sponsored request_signature so the FeedCache read by the tx is fresh at
// signing time. Implemented by `oraclerelay.Refresher` and wired in main; it
// filters the given FeedCache PDAs to the sponsored catalog (unknown caches are
// skipped). Declared here to avoid importing oraclerelay (no import cycle).
type OracleRefresher interface {
	RefreshIxs(ctx context.Context, feedCaches []solana.PublicKey) ([]solana.Instruction, error)
}

// RiskService is the contract for RT2 risk scoring. Evaluates transaction risk
// and returns a score with action. Satisfied directly by *risk.Service (no
// import cycle — internal/risk does not import internal/policy).
type RiskService interface {
	Evaluate(ctx context.Context, input *risk.EvaluateInput) (*risk.Score, error)
}

// RiskConfigService is the contract for RT2 policy management. Handles CRUD on
// dWallet and tenant risk configurations. Risk Layer is advisory-only: only
// warn_level is configurable. Satisfied directly by *risk.ConfigService.
type RiskConfigService interface {
	UpsertDWalletConfig(ctx context.Context, dwalletAddress, tenantID, warnLevel string, simulationEnabled bool) (*risk.RiskConfig, error)
	GetDWalletConfig(ctx context.Context, dwalletAddress string) (*risk.RiskConfig, error)
	DeleteDWalletConfig(ctx context.Context, dwalletAddress string) error
	UpsertTenantDefaults(ctx context.Context, tenantID, warnLevel string) (*risk.RiskTenantDefaults, error)
	GetTenantDefaults(ctx context.Context, tenantID string) (*risk.RiskTenantDefaults, error)
	AddToDenylist(ctx context.Context, tenantID, destination, reason string) error
	RemoveFromDenylist(ctx context.Context, tenantID, destination string) error
	AddToAllowlist(ctx context.Context, tenantID, destination, reason string) error
	RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error
}

// IkaSimulateClient is the contract for calling ika-backend simulation. Used to
// verify the digest matches before risk evaluation.
type IkaSimulateClient interface {
	SimulateTransaction(ctx context.Context, req *SimulateTransactionRequest) (*SimulateTransactionResponse, error)
}

// WithOracleRefresher wires refresh-on-sign for the gas-sponsored
// request_signature path. Optional; without it, signing relies on the managed
// crank / permissionless refresh for freshness.
func (s *Service) WithOracleRefresher(r OracleRefresher) *Service {
	s.oracleRefresher = r
	return s
}

// WithRiskService wires RT2 risk scoring for transaction evaluation.
// Optional; when set, evaluates destination risk before signing.
func (s *Service) WithRiskService(rs RiskService) *Service {
	s.riskService = rs
	return s
}

// WithRiskConfigService wires RT2 policy management.
// Optional; when set, enables /v1/policy/risk/* CRUD endpoints.
func (s *Service) WithRiskConfigService(rcs RiskConfigService) *Service {
	s.riskConfigService = rcs
	return s
}

// WithIkaSimulateClient wires RT2 digest verification via internal ika-backend.
// Optional; when set (along with riskService), verifies digest before risk evaluation.
func (s *Service) WithIkaSimulateClient(ic IkaSimulateClient) *Service {
	s.ikaSimulateClient = ic
	return s
}

// WithTenantResolver wires RT2 tenant resolution for risk CRUD routes.
// The resolver callback extracts the tenant ID from the authenticated request context.
// Used by /v1/policy/risk/* endpoints to scope dWallet and policy operations.
func (s *Service) WithTenantResolver(f func(*http.Request) (string, error)) *Service {
	s.tenantResolver = f
	return s
}

// AuditAppender is the minimal contract policy.Service needs from the
// gateway-wide `audit.Recorder` — we declare it locally to avoid a hard
// import cycle. The real recorder implements this surface.
type AuditAppender interface {
	AppendPolicyEngineEvent(ctx context.Context, ev PolicyEngineAuditEvent) error
}

// PolicyEngineAuditEvent is the per-submit payload appended to the tenant
// audit chain. Each field is plaintext (no PII / secrets); the chain
// signature in Vault makes the record tamper-evident.
type PolicyEngineAuditEvent struct {
	APIKeyID    string
	Action      string // e.g. "init", "rule.add", "rule.items.add", "request-signature"
	Engine      string // policy_engine PDA base58
	DWallet     string // dWallet pubkey base58
	TxSignature string // Solana signature of the landed tx
	ExtraJSON   string // JSON-encoded route-specific context (e.g. rule_kind, rule_index)
}

// WithAuditRecorder wires audit logging for /submit endpoints. The
// `resolveAPIKey` callback should return the API key id from the request
// context (gateway middleware sets it). Both args MUST be non-nil; pass
// nil/nil to opt out.
func (s *Service) WithAuditRecorder(
	a AuditAppender,
	resolveAPIKey func(*http.Request) (string, error),
) *Service {
	s.auditAppender = a
	s.resolveAPIKey = resolveAPIKey
	return s
}

// appendAuditSubmit records a successful /submit. No-op when audit is not
// wired. Errors are swallowed (logged by the recorder itself) — the tx
// landed, the caller does not need to learn the audit append failed.
func (s *Service) appendAuditSubmit(
	r *http.Request,
	action, engine, dwallet, txSig, extraJSON string,
) {
	if s.auditAppender == nil || s.resolveAPIKey == nil {
		return
	}
	keyID, err := s.resolveAPIKey(r)
	if err != nil || keyID == "" {
		return
	}
	_ = s.auditAppender.AppendPolicyEngineEvent(r.Context(), PolicyEngineAuditEvent{
		APIKeyID:    keyID,
		Action:      action,
		Engine:      engine,
		DWallet:     dwallet,
		TxSignature: txSig,
		ExtraJSON:   extraJSON,
	})
}

func NewService(programID solana.PublicKey) *Service {
	if programID.IsZero() {
		programID = solana.MustPublicKeyFromBase58("ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	}
	return &Service{ProgramID: programID}
}

// WithGasSponsor wires the gas sponsor. Returns the service for chaining.
func (s *Service) WithGasSponsor(sp *gasponsor.Signer) *Service {
	s.GasSponsor = sp
	return s
}

// WithRPC wires the Solana RPC client.
func (s *Service) WithRPC(c *rpc.Client) *Service {
	s.RPCClient = c
	return s
}

// MountRoutes registers `/v1/policy/*` under r. F2.6 scope (Allowlist
// vertical slice):
//
//	POST /v1/policy/init/challenge
//	POST /v1/policy/init/submit                                       → 501
//	POST /v1/policy/rules/add/challenge                               (Allowlist only)
//	POST /v1/policy/rules/add/submit                                  → 501
//	POST /v1/policy/rules/{ruleIndex}/items/add/challenge             (Allowlist destination)
//	POST /v1/policy/rules/{ruleIndex}/items/add/submit                → 501
//	POST /v1/policy/request-signature/challenge                       (runtime metadata digest)
//	POST /v1/policy/request-signature/submit                          → 501
func (s *Service) MountRoutes(r chi.Router) {
	r.Get("/v1/policy/{dwallet}", s.readPolicy)
	r.Post("/v1/policy/init/challenge", s.initChallenge)
	r.Post("/v1/policy/init/submit", s.initSubmit)

	r.Post("/v1/policy/rules/add/challenge", s.addRuleChallenge)
	r.Post("/v1/policy/rules/add/submit", s.addRuleSubmit)

	r.Post("/v1/policy/rules/{ruleIndex}/items/add/challenge", s.itemsAddChallenge)
	r.Post("/v1/policy/rules/{ruleIndex}/items/add/submit", s.itemsAddSubmit)

	r.Post("/v1/policy/request-signature/challenge", s.requestSignatureChallenge)
	r.Post("/v1/policy/request-signature/submit", s.requestSignatureSubmit)
	// On-demand (client-pays): returns the request_signature instruction for
	// client-side tx assembly (post_update + refresh_feed + this ix). No send.
	r.Post("/v1/policy/request-signature/build", s.requestSignatureBuild)

	// F11b-Phase1 — recover_as_primary (disc 80). Primary owner signs the
	// canonical challenge off-chain; gateway lands [precompile + main ix].
	r.Post("/v1/policy/recover-as-primary/challenge", s.recoverAsPrimaryChallenge)
	r.Post("/v1/policy/recover-as-primary/submit", s.recoverAsPrimarySubmit)

	// F11b-Phase2 — quorum_session_* (discs 82/83/85/86). Multi-tx M-of-N
	// recovery: primary opens, members contribute, anyone finalizes, recipient
	// closes for rent reclaim.
	r.Post("/v1/policy/quorum/session/open/challenge", s.quorumOpenChallenge)
	r.Post("/v1/policy/quorum/session/open/submit", s.quorumOpenSubmit)
	r.Post("/v1/policy/quorum/session/contribute/challenge", s.quorumContributeChallenge)
	r.Post("/v1/policy/quorum/session/contribute/submit", s.quorumContributeSubmit)
	r.Post("/v1/policy/quorum/session/finalize", s.quorumFinalize)
	r.Post("/v1/policy/quorum/session/close", s.quorumClose)

	// F11b-Phase2 — passkey_session_* (discs 89/90/91). Open with WebAuthn
	// assertion, use with ephemeral Ed25519 per signing, close for rent reclaim.
	r.Post("/v1/policy/passkey/session/open/challenge", s.passkeyOpenChallenge)
	r.Post("/v1/policy/passkey/session/open/submit", s.passkeyOpenSubmit)
	r.Post("/v1/policy/passkey/use/challenge", s.passkeyUseChallenge)
	r.Post("/v1/policy/passkey/use/submit", s.passkeyUseSubmit)
	r.Post("/v1/policy/passkey/session/close", s.passkeyClose)

	// RT2: Risk configuration management (CRUD operations).
	// Mounted only if riskConfigService is wired.
	if s.riskConfigService != nil {
		s.mountRiskRoutes(r)
	}
}

// ─── DTOs ───────────────────────────────────────────────────────────────────

type memberSlotJSON struct {
	Scheme        uint8  `json:"scheme" validate:"max=4"`
	IdentifierHex string `json:"identifier_hex" validate:"required"`
}

func (m memberSlotJSON) decode() ([MemberSlotLen]byte, error) {
	var out [MemberSlotLen]byte
	idBytes, err := hex.DecodeString(m.IdentifierHex)
	if err != nil {
		return out, errBadField("identifier_hex must be valid hex")
	}
	// Length expected by scheme (mirror andromeda_auth::idLenForScheme).
	expected := map[uint8]int{0: 32, 1: 20, 2: 33, 3: 33, 4: 32}
	if exp, ok := expected[m.Scheme]; !ok || len(idBytes) != exp {
		return out, errBadField("identifier_hex length doesn't match scheme")
	}
	out[0] = m.Scheme
	copy(out[1:], idBytes)
	return out, nil
}

type errBadField string

func (e errBadField) Error() string { return string(e) }

func mustHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errBadField("expected 32-byte hex")
	}
	copy(out[:], b)
	return out, nil
}

// ─── /v1/policy/init/challenge ──────────────────────────────────────────────

type initChallengeRequest struct {
	DwalletAddress      string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthoritySlot   memberSlotJSON `json:"init_authority_slot" validate:"required"`
	OwnerSlot           memberSlotJSON `json:"owner_slot" validate:"required"`
	DefaultRecoveryHash string         `json:"default_recovery_hash,omitempty" validate:"omitempty,hex_len=32"`
}

type initChallengeResponse struct {
	ProgramID         string `json:"program_id"`
	EngineAddress     string `json:"engine_address"`
	InitAuthorityHash string `json:"init_authority_hash_hex"`
	Domain            string `json:"domain"`
	OpTag             string `json:"op_tag"`
	PreimageHex       string `json:"preimage_hex"`
	ChallengeHex      string `json:"challenge_hex"`
}

func (s *Service) initChallenge(w http.ResponseWriter, r *http.Request) {
	var req initChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
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
	opTag := OpInit
	if req.DefaultRecoveryHash != "" {
		recoveryHash, err = mustHex32(req.DefaultRecoveryHash)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "default_recovery_hash: "+err.Error())
			return
		}
		present = 1
		opTag = OpInitWithRecovery
	}

	preimage, challenge := initChallengePreimageAndHash(
		dwallet, initSlot, ownerSlot, present, recoveryHash,
	)
	httpx.WriteJSON(w, http.StatusOK, initChallengeResponse{
		ProgramID:         s.ProgramID.String(),
		EngineAddress:     engine.String(),
		InitAuthorityHash: hex.EncodeToString(initHash[:]),
		Domain:            string(DomainInitV1),
		OpTag:             string(opTag),
		PreimageHex:       hex.EncodeToString(preimage),
		ChallengeHex:      hex.EncodeToString(challenge[:]),
	})
}

// ─── /v1/policy/rules/add/challenge ─────────────────────────────────────────

type addRuleRequest struct {
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	RuleIndex         uint8          `json:"rule_index" validate:"max=15"`
	RuleGeneration    uint32         `json:"rule_generation"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	AppliesTo         uint8          `json:"applies_to" validate:"required,min=1,max=7"`
	// Oracle (rule_kind=4) + SpendingUsd (rule_kind=9). Both are the on-chain
	// divided forms: freshness_seconds = value × 16; confidence_bps = value × 4
	// (0 disables the confidence check). Ignored for other kinds.
	FreshnessSecondsDiv16 uint8 `json:"freshness_seconds_div16,omitempty"`
	MinConfidenceBpsDiv4  uint8 `json:"min_confidence_bps_div4,omitempty"`
	// SpendingUsd-only (rule_kind=9). USD ceilings, canonical 1e8; 0 disables
	// the corresponding window.
	MaxPerTxUsd   uint64 `json:"max_per_tx_usd,omitempty"`
	MaxPerDayUsd  uint64 `json:"max_per_day_usd,omitempty"`
	MaxPerWeekUsd uint64 `json:"max_per_week_usd,omitempty"`
}

type addRuleChallengeResponse struct {
	ProgramID     string `json:"program_id"`
	EngineAddress string `json:"engine_address"`
	RulePDA       string `json:"rule_pda"`
	OpTag         string `json:"op_tag"`
	HumanMessage  string `json:"human_message"`
	ConfigHashHex string `json:"config_hash_hex"`
	PreimageHex   string `json:"preimage_hex"`
	ChallengeHex  string `json:"challenge_hex"`
}

func (s *Service) addRuleChallenge(w http.ResponseWriter, r *http.Request) {
	var req addRuleRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	switch RuleKind(req.RuleKind) {
	case KindAllowlist:
		s.addRuleAllowlistChallenge(w, req)
	case KindOracle:
		s.addRuleOracleChallenge(w, req)
	case KindSpendingUsd:
		s.addRuleSpendingUsdChallenge(w, req)
	default:
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"rule_kind must be 1 (Allowlist), 4 (Oracle) or 9 (SpendingUsd)")
	}
}

func (s *Service) addRuleAllowlistChallenge(w http.ResponseWriter, req addRuleRequest) {
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
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindAllowlist, req.RuleIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	emptyDest := make([]byte, 1024)
	configHash, err := AllowlistConfigHash(req.AppliesTo, 0, emptyDest)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	human := HumanMessageAllowlistPause(engine, dwallet)
	gen := req.RuleGeneration
	if gen == 0 {
		gen = 1 // first add bumps generation 0 → 1
	}
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], gen)

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
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, addRuleChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpAddAllowlist),
		HumanMessage:  string(human),
		ConfigHashHex: hex.EncodeToString(configHash[:]),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

// addRuleOracleChallenge builds the disc 13 (add_rule_oracle) admin challenge.
// The on-chain handler reuses the allowlist-pause human message and seeds an
// empty feed list (feeds_count=0); feeds are appended later via disc 122.
func (s *Service) addRuleOracleChallenge(w http.ResponseWriter, req addRuleRequest) {
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
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindOracle, req.RuleIndex)
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
	gen := req.RuleGeneration
	if gen == 0 {
		gen = 1 // first add bumps generation 0 → 1
	}
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], gen)

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
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, addRuleChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpAddOracle),
		HumanMessage:  string(human),
		ConfigHashHex: hex.EncodeToString(configHash[:]),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

// ─── /v1/policy/rules/{ruleIndex}/items/add/challenge ───────────────────────

type itemsAddRequest struct {
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	RuleGeneration    uint32         `json:"rule_generation" validate:"required,min=1"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	// Allowlist item (rule_kind=1).
	DestinationHex string `json:"destination_hex,omitempty" validate:"omitempty,hex_len=32"`
	// Oracle feed (rule_kind=4). FeedAccount is the adapter FeedCache PDA;
	// FeedOwner is the Pyth adapter program id (must be allowlisted on-chain).
	// MinQ64/MaxQ64 are the canonical 1e8 price band (min <= max).
	FeedAccount string `json:"feed_account,omitempty" validate:"omitempty,solana_pubkey"`
	FeedOwner   string `json:"feed_owner,omitempty" validate:"omitempty,solana_pubkey"`
	MinQ64      int64  `json:"min_q64,omitempty"`
	MaxQ64      int64  `json:"max_q64,omitempty"`
	// SpendingUsd feed (rule_kind=9). FeedAccount (reused above) is the Pyth
	// adapter FeedCache PDA; Decimals is the asset's base-unit decimal count.
	Decimals uint8 `json:"decimals,omitempty" validate:"max=24"`
}

type itemsAddChallengeResponse struct {
	ProgramID     string `json:"program_id"`
	EngineAddress string `json:"engine_address"`
	RulePDA       string `json:"rule_pda"`
	OpTag         string `json:"op_tag"`
	HumanMessage  string `json:"human_message"`
	PreimageHex   string `json:"preimage_hex"`
	ChallengeHex  string `json:"challenge_hex"`
}

func (s *Service) itemsAddChallenge(w http.ResponseWriter, r *http.Request) {
	ruleIndexStr := chi.URLParam(r, "ruleIndex")
	ruleIndex, err := strconv.Atoi(ruleIndexStr)
	if err != nil || ruleIndex < 0 || ruleIndex >= MaxRules {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_rule_index",
			"ruleIndex must be 0..15")
		return
	}

	var req itemsAddRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	switch RuleKind(req.RuleKind) {
	case KindAllowlist:
		s.itemsAddAllowlistChallenge(w, req, uint8(ruleIndex))
	case KindOracle:
		s.itemsAddOracleChallenge(w, req, uint8(ruleIndex))
	case KindSpendingUsd:
		s.itemsAddSpendingUsdChallenge(w, req, uint8(ruleIndex))
	default:
		httpx.WriteError(w, http.StatusNotImplemented, "kind_not_supported_yet",
			"rule_kind must be 1 (Allowlist), 4 (Oracle) or 9 (SpendingUsd)")
	}
}

func (s *Service) itemsAddAllowlistChallenge(w http.ResponseWriter, req itemsAddRequest, ruleIndex uint8) {
	if req.DestinationHex == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "destination_hex is required for rule_kind=1")
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}
	dest, _ := mustHex32(req.DestinationHex)

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindAllowlist, ruleIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	human := HumanMessageAllowlistAddDestination(dest, engine, dwallet)
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], req.RuleGeneration)

	ch := &AdminChallengeInput{
		OpTag:          OpAllowlistAddDest,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindAllowlist),
		RuleIndex:      ruleIndex,
		RuleGeneration: req.RuleGeneration,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     [32]byte{}, // matches the placeholder in lib.rs disc 120
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{dest[:], genLE[:]},
	}
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, itemsAddChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpAllowlistAddDest),
		HumanMessage:  string(human),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

// itemsAddOracleChallenge builds the disc 122 (update_rule_oracle_add_feed)
// admin challenge. rule_generation must be the post-update value (current+1).
func (s *Service) itemsAddOracleChallenge(w http.ResponseWriter, req itemsAddRequest, ruleIndex uint8) {
	feedAccount, feedOwner, ok := decodeOracleFeed(w, req.FeedAccount, req.FeedOwner, req.MinQ64, req.MaxQ64)
	if !ok {
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
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindOracle, ruleIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	human := HumanMessageOracleAddFeed(feedAccount, feedOwner, req.MinQ64, req.MaxQ64, engine, dwallet)
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], req.RuleGeneration)
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
		ConfigHash:     [32]byte{}, // placeholder per lib.rs disc 122
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{fa, fo, minLE[:], maxLE[:], genLE[:]},
	}
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, itemsAddChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpOracleAddFeed),
		HumanMessage:  string(human),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

// decodeOracleFeed validates + decodes the oracle feed fields shared by the
// items/add oracle challenge and submit handlers. Writes the HTTP error and
// returns ok=false on any invalid field.
func decodeOracleFeed(w http.ResponseWriter, feedAccountStr, feedOwnerStr string, minQ64, maxQ64 int64) (feedAccount, feedOwner solana.PublicKey, ok bool) {
	if feedAccountStr == "" || feedOwnerStr == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field",
			"feed_account and feed_owner are required for rule_kind=4")
		return feedAccount, feedOwner, false
	}
	if minQ64 > maxQ64 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "min_q64 must be <= max_q64")
		return feedAccount, feedOwner, false
	}
	feedAccount, err := solana.PublicKeyFromBase58(feedAccountStr)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_account must be base58")
		return feedAccount, feedOwner, false
	}
	feedOwner, err = solana.PublicKeyFromBase58(feedOwnerStr)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_owner must be base58")
		return feedAccount, feedOwner, false
	}
	return feedAccount, feedOwner, true
}

func int64LE(v int64) [8]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	return b
}

// ─── /v1/policy/request-signature/challenge ─────────────────────────────────

type requestSignatureChallengeRequest struct {
	DwalletAddress    string `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	MessageDigestHex  string `json:"message_digest_hex" validate:"required,hex_len=32"`
	DestinationHex    string `json:"destination_hex" validate:"required,hex_len=32"`
	UserPubkeyHex     string `json:"user_pubkey_hex" validate:"required,hex_len=32"`
	SignatureScheme   uint16 `json:"signature_scheme" validate:"max=6"` // DWalletSignatureScheme 0..6 (5=EddsaSha512 Solana/Sui, 6=SchnorrkelMerlin)
	Path              uint8  `json:"path" validate:"required,min=1,max=7"`
	RulesGeneration   uint32 `json:"rules_generation"`
	// Update 3 (ABI V2): asset amount (base units) + index in the active
	// KIND_SPENDING_USD allowlist. Default 0/0 when no spending rule applies.
	Amount     uint64 `json:"amount,omitempty"`
	AssetIndex uint8  `json:"asset_index,omitempty" validate:"max=15"`
}

// riskAdvisory represents optional advisory information about transaction risk.
// Attached to challenge/submit responses when Risk Layer evaluates risk.
type riskAdvisory struct {
	Level   string   `json:"level"`   // "none" | "low" | "medium" | "high" | "critical"
	Reasons []string `json:"reasons"` // sanitized risk factors (advisory only)
}

type requestSignatureChallengeResponse struct {
	EngineAddress  string `json:"engine_address"`
	MetadataDigest string `json:"metadata_digest_hex"`
	PreimageHex    string `json:"preimage_hex"`
}

func (s *Service) requestSignatureChallenge(w http.ResponseWriter, r *http.Request) {
	var req requestSignatureChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	msgDigest, _ := mustHex32(req.MessageDigestHex)
	dest, _ := mustHex32(req.DestinationHex)
	userPK, _ := mustHex32(req.UserPubkeyHex)

	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	in := &RequestMetadataDigestInput{
		Engine:          engine,
		DWallet:         dwallet,
		MessageDigest:   msgDigest,
		Destination:     dest,
		UserPubkey:      userPK,
		SignatureScheme: req.SignatureScheme,
		Path:            req.Path,
		RulesGeneration: req.RulesGeneration,
		Amount:          req.Amount,
		AssetIndex:      req.AssetIndex,
	}
	pre := in.Preimage()
	digest := in.Hash()

	// Update 2 Part A: kick off the presign now (during the human review/sign
	// window), keyed by the metadata digest the submit will replay. Non-fatal.
	s.firePresignPrefetch(r, req.DwalletAddress, hex.EncodeToString(digest[:]))
	httpx.WriteJSON(w, http.StatusOK, requestSignatureChallengeResponse{
		EngineAddress:  engine.String(),
		MetadataDigest: hex.EncodeToString(digest[:]),
		PreimageHex:    hex.EncodeToString(pre),
	})
}

// ─── internal helpers (avoid stdlib import dance) ───────────────────────────

func initChallengePreimageAndHash(
	dwallet solana.PublicKey,
	initSlot, ownerSlot [MemberSlotLen]byte,
	defaultRecoveryPresent uint8,
	defaultRecoveryHash [32]byte,
) ([]byte, [32]byte) {
	opTag := OpInit
	if defaultRecoveryPresent == 1 {
		opTag = OpInitWithRecovery
	}
	pre := make([]byte, 0, 128)
	pre = append(pre, DomainInitV1...)
	pre = append(pre, opTag...)
	pre = append(pre, dwallet.Bytes()...)
	pre = append(pre, initSlot[:]...)
	pre = append(pre, ownerSlot[:]...)
	pre = append(pre, defaultRecoveryPresent)
	pre = append(pre, defaultRecoveryHash[:]...)
	return pre, sha256Sum(pre)
}
