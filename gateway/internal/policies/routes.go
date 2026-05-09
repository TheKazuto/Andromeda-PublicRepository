package policies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
)

// APIKeyResolver pulls the authenticated api_key_id from the request context.
type APIKeyResolver func(r *http.Request) (uuid.UUID, error)

type Service struct {
	Registry           *Registry
	RPCClient          *rpc.Client
	GasSponsor         *gasponsor.Signer
	Subscriptions      *SubscriptionsStore
	ResolveAPIKeyID    APIKeyResolver
	SDKBaseURL         string
	SDKVersionTag      string
	ConfidentialClient ConfidentialSignClient
}

func NewService(reg *Registry, rpcURL string) (*Service, error) {
	if rpcURL == "" {
		return nil, errors.New("SOLANA_RPC_URL is required for policies")
	}
	return &Service{
		Registry:  reg,
		RPCClient: rpc.New(rpcURL),
	}, nil
}

// WithGasSponsor wires the Andromeda gas sponsor signer. The gateway pays
// Solana fees for every challenge-based admin / init / request-signature
// flow under /v1/policies and /v1/signatures. Without it those endpoints
// return 503.
func (s *Service) WithGasSponsor(sp *gasponsor.Signer) *Service {
	s.GasSponsor = sp
	return s
}

func (s *Service) WithSubscriptions(store *SubscriptionsStore, resolver APIKeyResolver) *Service {
	s.Subscriptions = store
	s.ResolveAPIKeyID = resolver
	return s
}

func (s *Service) WithSDKArtifacts(baseURL, versionTag string) *Service {
	s.SDKBaseURL = baseURL
	s.SDKVersionTag = versionTag
	return s
}

func (s *Service) WithConfidentialClient(c ConfidentialSignClient) *Service {
	s.ConfidentialClient = c
	return s
}

// MountRoutes registers the policies endpoints under /v1/policies. All flows
// are gas-sponsored: the dev's app talks to the gateway over HTTP; the user
// signs only off-chain challenges with whatever wallet they have.
//
//	GET  /v1/policies/templates
//	POST /v1/policies/{template}/init
//	POST /v1/policies/{template}/admin/challenge
//	POST /v1/policies/{template}/admin/submit
//	POST /v1/policies/{template}/request-signature
//	POST /v1/signatures/simulate
//	POST /v1/signatures/batch
//	POST /v1/confidential/sign
func (s *Service) MountRoutes(r chi.Router) {
	r.Get("/v1/policies/templates", s.listTemplates)
	r.Post("/v1/policies/{template}/init", s.initPolicy)
	r.Post("/v1/policies/{template}/admin/challenge", s.adminChallenge)
	r.Post("/v1/policies/{template}/admin/submit", s.adminSubmit)
	r.Post("/v1/policies/{template}/request-signature", s.requestSignature)
	r.Post("/v1/signatures/simulate", s.simulate)
	r.Post("/v1/signatures/batch", s.batch)
	r.Post("/v1/confidential/sign", s.confidentialSign)
}

func (s *Service) listTemplates(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, t := range AllTemplates {
		entry := map[string]any{
			"name":           t.Name,
			"display_name":   t.DisplayName,
			"description":    t.Description,
			"mutable_fields": t.Mutable,
			"seeds":          t.Seeds,
			"deployed":       false,
		}
		if pid, ok := s.Registry.ProgramIDs[t.Name]; ok {
			entry["program_id"] = pid.String()
			entry["deployed"] = true
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ── DTOs ───────────────────────────────────────────────────────

type ownerSlotJSON struct {
	Scheme           uint8  `json:"scheme"`
	IdentifierBase64 string `json:"identifier_base64"`
}

func decodeOwnerSlot(in ownerSlotJSON) ([auth.MemberSlotLen]byte, error) {
	var slot [auth.MemberSlotLen]byte
	idBytes, err := base64.StdEncoding.DecodeString(in.IdentifierBase64)
	if err != nil {
		return slot, fmt.Errorf("invalid identifier_base64: %w", err)
	}
	return auth.BuildMemberSlot(in.Scheme, idBytes)
}

type initRequest struct {
	DwalletAddress string        `json:"dwallet_address"`
	OwnerSlot      ownerSlotJSON `json:"owner_slot"`

	// Audit C2 (Opção 4): init_authority signs an off-chain challenge
	// over all init params. The hash of the slot is part of the PDA seed,
	// so each (dwallet, init_authority) pair maps to a distinct policy
	// PDA — squat-resistant.
	InitAuthoritySlot              ownerSlotJSON `json:"init_authority_slot"`
	InitAuthoritySignatureBase64   string        `json:"init_authority_signature_base64"`
	InitAuthorityWebauthnAuthData  string        `json:"init_authority_webauthn_auth_data_base64,omitempty"`
	InitAuthorityWebauthnCDJ       string        `json:"init_authority_webauthn_cdj_base64,omitempty"`

	// Audit H6: required for session-keys to support multiple sessions
	// per dwallet — each session_index produces a distinct PDA.
	SessionIndex *uint32 `json:"session_index,omitempty"`

	// session-keys init params
	SessionKey     string  `json:"session_key,omitempty"`
	ExpiresAtSlot  *uint64 `json:"expires_at_slot,omitempty"`
	MaxAmountPerTx *uint64 `json:"max_amount_per_tx,omitempty"`
	MaxUses        *uint32 `json:"max_uses,omitempty"`

	MaxSigsPerWindow     *uint32 `json:"max_sigs_per_window,omitempty"`
	WindowSlots          *uint64 `json:"window_slots,omitempty"`
	Mode                 *uint8  `json:"mode,omitempty"`
	StartSlot            *uint64 `json:"start_slot,omitempty"`
	EndSlot              *uint64 `json:"end_slot,omitempty"`
	RecurringPeriodSlots *uint64 `json:"recurring_period_slots,omitempty"`
	OracleFeed           string  `json:"oracle_feed,omitempty"`
	MinPrice             *int64  `json:"min_price,omitempty"`
	MaxPrice             *int64  `json:"max_price,omitempty"`
	MaxAgeSlots          *uint64 `json:"max_age_slots,omitempty"`
	MaxConfidenceBps     *uint16 `json:"max_confidence_bps,omitempty"` // Audit M1: 0 (or omit) = disabled.
	ThresholdAmount      *uint64 `json:"threshold_amount,omitempty"`
	PasskeyPubkeyB64     string  `json:"passkey_pubkey_base64,omitempty"`
	FHEAuthority         string  `json:"fhe_authority,omitempty"`
	DecisionMaxAgeSlots  *uint64 `json:"decision_max_age_slots,omitempty"`
}

// decodeInitContext parses the audit-C2 init_authority fields from an HTTP
// request and returns a populated InitContext. The handler still resolves
// dwallet, sponsor and OwnerSlot separately (those are template-agnostic).
func decodeInitContext(req *initRequest, dwallet, sponsor solana.PublicKey) (InitContext, error) {
	authoritySlot, err := decodeOwnerSlot(req.InitAuthoritySlot)
	if err != nil {
		return InitContext{}, fmt.Errorf("init_authority_slot: %w", err)
	}
	if req.InitAuthoritySignatureBase64 == "" {
		return InitContext{}, errors.New("init_authority_signature_base64 is required (Audit C2)")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(req.InitAuthoritySignatureBase64)
	if err != nil {
		return InitContext{}, fmt.Errorf("init_authority_signature_base64: %w", err)
	}
	initSig := AdminSignature{Signature: sigBytes}
	if req.InitAuthorityWebauthnAuthData != "" {
		raw, derr := base64.StdEncoding.DecodeString(req.InitAuthorityWebauthnAuthData)
		if derr != nil {
			return InitContext{}, fmt.Errorf("init_authority_webauthn_auth_data: %w", derr)
		}
		initSig.WebauthnAuthData = raw
	}
	if req.InitAuthorityWebauthnCDJ != "" {
		raw, derr := base64.StdEncoding.DecodeString(req.InitAuthorityWebauthnCDJ)
		if derr != nil {
			return InitContext{}, fmt.Errorf("init_authority_webauthn_cdj: %w", derr)
		}
		initSig.WebauthnClientDataJSON = raw
	}
	return InitContext{
		Dwallet:           dwallet,
		InitAuthoritySlot: authoritySlot,
		InitAuthorityHash: InitAuthorityHashFromSlot(authoritySlot),
		InitSig:           initSig,
		Sponsor:           sponsor,
	}, nil
}

func (s *Service) requireSponsor(w http.ResponseWriter) bool {
	if s.GasSponsor == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_gas_sponsor",
			"ANDROMEDA_GAS_SPONSOR_KEYPAIR is not configured")
		return false
	}
	return true
}

func (s *Service) initPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireSponsor(w) {
		return
	}
	template := strings.ToLower(chi.URLParam(r, "template"))
	var req initRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", "dwallet_address must be base58")
		return
	}
	ownerSlot, err := decodeOwnerSlot(req.OwnerSlot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_owner_slot", err.Error())
		return
	}
	sponsor := s.GasSponsor.PublicKey()

	// Audit C2 (Opção 4): every init carries an init_authority precompile
	// signature. decodeInitContext parses + validates the inputs.
	initCtx, err := decodeInitContext(&req, dwallet, sponsor)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_init_authority", err.Error())
		return
	}

	var ixs []solana.Instruction
	switch template {
	case TemplateAllowlist:
		ixs2, berr := BuildAllowlistInit(s.Registry, AllowlistInitInput{
			InitContext: initCtx,
			OwnerSlot:   ownerSlot,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplateVelocityGuard:
		if req.MaxSigsPerWindow == nil || req.WindowSlots == nil {
			writeErr(w, http.StatusBadRequest, "missing_args", "max_sigs_per_window, window_slots required")
			return
		}
		ixs2, berr := BuildVelocityInit(s.Registry, VelocityInitInput{
			InitContext:      initCtx,
			OwnerSlot:        ownerSlot,
			MaxSigsPerWindow: *req.MaxSigsPerWindow,
			WindowSlots:      *req.WindowSlots,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplateTimeLock:
		if req.Mode == nil || req.StartSlot == nil || req.EndSlot == nil || req.RecurringPeriodSlots == nil {
			writeErr(w, http.StatusBadRequest, "missing_args", "mode, start_slot, end_slot, recurring_period_slots required")
			return
		}
		ixs2, berr := BuildTimeLockInit(s.Registry, TimeLockInitInput{
			InitContext:          initCtx,
			OwnerSlot:            ownerSlot,
			Mode:                 *req.Mode,
			StartSlot:            *req.StartSlot,
			EndSlot:              *req.EndSlot,
			RecurringPeriodSlots: *req.RecurringPeriodSlots,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplateOracleConditional:
		if req.MinPrice == nil || req.MaxPrice == nil || req.MaxAgeSlots == nil || req.OracleFeed == "" {
			writeErr(w, http.StatusBadRequest, "missing_args", "oracle_feed, min_price, max_price, max_age_slots required")
			return
		}
		feed, ferr := solana.PublicKeyFromBase58(req.OracleFeed)
		if ferr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_oracle_feed", ferr.Error())
			return
		}
		var maxConfBps uint16
		if req.MaxConfidenceBps != nil {
			maxConfBps = *req.MaxConfidenceBps
		}
		ixs2, berr := BuildOracleInit(s.Registry, OracleInitInput{
			InitContext:      initCtx,
			OwnerSlot:        ownerSlot,
			OracleFeed:       feed,
			MinPrice:         *req.MinPrice,
			MaxPrice:         *req.MaxPrice,
			MaxAgeSlots:      *req.MaxAgeSlots,
			MaxConfidenceBps: maxConfBps,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplatePasskeyStepUp:
		if req.ThresholdAmount == nil || req.PasskeyPubkeyB64 == "" {
			writeErr(w, http.StatusBadRequest, "missing_args", "threshold_amount, passkey_pubkey_base64 required")
			return
		}
		pkb, derr := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
		if derr != nil || len(pkb) != 33 {
			writeErr(w, http.StatusBadRequest, "invalid_passkey_pubkey", "must decode to 33 bytes")
			return
		}
		var pk [33]byte
		copy(pk[:], pkb)
		ixs2, berr := BuildPasskeyInit(s.Registry, PasskeyInitInput{
			InitContext:     initCtx,
			OwnerSlot:       ownerSlot,
			ThresholdAmount: *req.ThresholdAmount,
			PasskeyPubkey:   pk,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplateFHEGated:
		if req.FHEAuthority == "" || req.DecisionMaxAgeSlots == nil {
			writeErr(w, http.StatusBadRequest, "missing_args", "fhe_authority, decision_max_age_slots required")
			return
		}
		fa, ferr := solana.PublicKeyFromBase58(req.FHEAuthority)
		if ferr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_fhe_authority", ferr.Error())
			return
		}
		ixs2, berr := BuildFHEGatedInit(s.Registry, FHEGatedInitInput{
			InitContext:         initCtx,
			OwnerSlot:           ownerSlot,
			FHEAuthority:        fa,
			DecisionMaxAgeSlots: *req.DecisionMaxAgeSlots,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	case TemplateSessionKeys:
		// Audit H6: session_index is required to support multiple sessions.
		if req.SessionIndex == nil {
			writeErr(w, http.StatusBadRequest, "missing_args", "session_index required (Audit H6)")
			return
		}
		if req.SessionKey == "" || req.ExpiresAtSlot == nil || req.MaxAmountPerTx == nil || req.MaxUses == nil {
			writeErr(w, http.StatusBadRequest, "missing_args", "session_key, expires_at_slot, max_amount_per_tx, max_uses required")
			return
		}
		sk, sErr := solana.PublicKeyFromBase58(req.SessionKey)
		if sErr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_session_key", sErr.Error())
			return
		}
		ixs2, berr := BuildSessionKeysCreate(s.Registry, SessionKeysCreateSessionInput{
			InitContext:    initCtx,
			SessionIndex:   *req.SessionIndex,
			OwnerSlot:      ownerSlot,
			SessionKey:     sk,
			ExpiresAtSlot:  *req.ExpiresAtSlot,
			MaxAmountPerTx: *req.MaxAmountPerTx,
			MaxUses:        *req.MaxUses,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ixs = ixs2
	default:
		writeErr(w, http.StatusNotFound, "unknown_template", template+" is not a known template")
		return
	}

	sig, err := s.GasSponsor.SignAndSend(r.Context(), ixs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "send_failed", err.Error())
		return
	}
	progID, _ := s.Registry.ProgramID(template)
	var policyPda solana.PublicKey
	if template == TemplateSessionKeys && req.SessionIndex != nil {
		policyPda, _, _ = SessionKeyPolicyPDA(progID, dwallet, initCtx.InitAuthorityHash, *req.SessionIndex)
	} else {
		policyPda, _, _ = PolicyPDA(template, progID, dwallet, initCtx.InitAuthorityHash)
	}
	if s.Subscriptions != nil && s.ResolveAPIKeyID != nil {
		if apiKeyID, rerr := s.ResolveAPIKeyID(r); rerr == nil && apiKeyID != uuid.Nil {
			subCtx, subCancel := context.WithTimeout(r.Context(), 3*time.Second)
			_ = s.Subscriptions.Subscribe(subCtx, apiKeyID,
				policyPda.String(), template, progID.String(), dwallet.String())
			subCancel()
		}
	}
	resp := map[string]any{
		"tx_signature":        sig.String(),
		"policy_address":      policyPda.String(),
		"program_id":          progID.String(),
		"init_authority_hash": base64.StdEncoding.EncodeToString(initCtx.InitAuthorityHash[:]),
	}
	if req.SessionIndex != nil {
		resp["session_index"] = *req.SessionIndex
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── Admin challenge / submit ───────────────────────────────────

type adminChallengeRequest struct {
	DwalletAddress    string        `json:"dwallet_address"`
	OwnerSlot         ownerSlotJSON `json:"owner_slot"`

	// Audit C2 (Opção 4): client supplies the init_authority_hash that
	// produced this policy's PDA. The gateway does NOT recompute it from
	// init_authority_slot here — the slot is only signed at init time and
	// not stored client-side; only the hash is needed to identify which
	// PDA to address. (For session-keys also session_index — Audit H6.)
	InitAuthorityHashBase64 string `json:"init_authority_hash_base64"`
	SessionIndex            *uint32 `json:"session_index,omitempty"`

	Action            string        `json:"action"`
	ExpectedNonce     uint64        `json:"expected_nonce"`
	DestinationBase64 string        `json:"destination_base64,omitempty"`
	MaxSigsPerWindow  *uint32       `json:"max_sigs_per_window,omitempty"`
	WindowSlots       *uint64       `json:"window_slots,omitempty"`
	Mode              *uint8        `json:"mode,omitempty"`
	StartSlot         *uint64       `json:"start_slot,omitempty"`
	EndSlot           *uint64       `json:"end_slot,omitempty"`
	RecurringPeriodSlots *uint64    `json:"recurring_period_slots,omitempty"`
	MinPrice          *int64        `json:"min_price,omitempty"`
	MaxPrice          *int64        `json:"max_price,omitempty"`
	MaxAgeSlots       *uint64       `json:"max_age_slots,omitempty"`
	MaxConfidenceBps  *uint16       `json:"max_confidence_bps,omitempty"` // Audit M1: 0 (or omit) = disabled.
	ThresholdAmount   *uint64       `json:"threshold_amount,omitempty"`
	PasskeyPubkeyB64  string        `json:"passkey_pubkey_base64,omitempty"`
	NewFHEAuthority   string        `json:"new_fhe_authority,omitempty"`
	AllowedProgram    string        `json:"allowed_program,omitempty"`
	Recipient         string        `json:"recipient,omitempty"`
}

// decodeInitAuthorityHash parses the base64 [u8; 32] init_authority_hash
// field. Returns an error if missing or wrong length — every admin /
// request-signature flow needs it after Audit C2.
func decodeInitAuthorityHash(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, errors.New("init_authority_hash_base64 is required (Audit C2)")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("init_authority_hash_base64: %w", err)
	}
	if len(raw) != 32 {
		return out, errors.New("init_authority_hash_base64 must decode to 32 bytes")
	}
	copy(out[:], raw)
	return out, nil
}

// adminChallenge returns the canonical challenge bytes the owner must sign.
// The caller passes `expected_nonce` (read separately on-chain) — the on-chain
// program rejects with `InvalidNonce` if it doesn't match.
func (s *Service) adminChallenge(w http.ResponseWriter, r *http.Request) {
	template := strings.ToLower(chi.URLParam(r, "template"))
	var req adminChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", "dwallet_address must be base58")
		return
	}
	ownerSlot, err := decodeOwnerSlot(req.OwnerSlot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_owner_slot", err.Error())
		return
	}
	challenge, err := computeAdminChallenge(template, req, dwallet, ownerSlot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "challenge_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_base64": base64.StdEncoding.EncodeToString(challenge[:]),
		"expected_nonce":   req.ExpectedNonce,
	})
}

func computeAdminChallenge(template string, req adminChallengeRequest, dwallet solana.PublicKey, ownerSlot [auth.MemberSlotLen]byte) ([32]byte, error) {
	var zero [32]byte
	switch template {
	case TemplateAllowlist:
		switch req.Action {
		case "add_destination", "remove_destination":
			dest, derr := decodeBase58OrBase64Bytes32(req.DestinationBase64)
			if derr != nil {
				return zero, fmt.Errorf("destination: %w", derr)
			}
			if req.Action == "add_destination" {
				return auth.AllowlistAddDestinationChallenge(dwallet, dest, req.ExpectedNonce, ownerSlot), nil
			}
			return auth.AllowlistRemoveDestinationChallenge(dwallet, dest, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.AllowlistPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.AllowlistResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateVelocityGuard:
		switch req.Action {
		case "update_window":
			if req.MaxSigsPerWindow == nil || req.WindowSlots == nil {
				return zero, errors.New("max_sigs_per_window and window_slots required")
			}
			return auth.VelocityUpdateWindowChallenge(dwallet, *req.MaxSigsPerWindow, *req.WindowSlots, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.VelocityPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.VelocityResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateTimeLock:
		switch req.Action {
		case "update_window":
			if req.Mode == nil || req.StartSlot == nil || req.EndSlot == nil || req.RecurringPeriodSlots == nil {
				return zero, errors.New("mode, start_slot, end_slot, recurring_period_slots required")
			}
			return auth.TimeLockUpdateWindowChallenge(dwallet, *req.Mode, *req.StartSlot, *req.EndSlot, *req.RecurringPeriodSlots, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.TimeLockPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.TimeLockResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateOracleConditional:
		switch req.Action {
		case "update_bounds":
			if req.MinPrice == nil || req.MaxPrice == nil || req.MaxAgeSlots == nil {
				return zero, errors.New("min_price, max_price, max_age_slots required")
			}
			var maxConfBps uint16
			if req.MaxConfidenceBps != nil {
				maxConfBps = *req.MaxConfidenceBps
			}
			return auth.OracleUpdateBoundsChallenge(dwallet, *req.MinPrice, *req.MaxPrice, *req.MaxAgeSlots, maxConfBps, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.OraclePauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.OracleResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplatePasskeyStepUp:
		switch req.Action {
		case "update_policy":
			if req.ThresholdAmount == nil || req.PasskeyPubkeyB64 == "" {
				return zero, errors.New("threshold_amount and passkey_pubkey_base64 required")
			}
			pkb, derr := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
			if derr != nil || len(pkb) != 33 {
				return zero, errors.New("passkey_pubkey_base64 must decode to 33 bytes")
			}
			var pk [33]byte
			copy(pk[:], pkb)
			return auth.PasskeyUpdatePolicyChallenge(dwallet, *req.ThresholdAmount, pk, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.PasskeyPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.PasskeyResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateFHEGated:
		switch req.Action {
		case "rotate_authority":
			if req.NewFHEAuthority == "" {
				return zero, errors.New("new_fhe_authority required")
			}
			fa, ferr := solana.PublicKeyFromBase58(req.NewFHEAuthority)
			if ferr != nil {
				return zero, fmt.Errorf("new_fhe_authority: %w", ferr)
			}
			return auth.FHEGatedRotateAuthorityChallenge(dwallet, fa, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.FHEGatedPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.FHEGatedResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateSessionKeys:
		// Audit C2 (Opção 4): create_session is now an init_policy flow,
		// not an admin action — use POST /v1/policies/session-keys/init.
		switch req.Action {
		case "revoke":
			return auth.SessionKeysRevokeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "add_allowed_program", "remove_allowed_program":
			if req.AllowedProgram == "" {
				return zero, errors.New("allowed_program required")
			}
			pid, perr := solana.PublicKeyFromBase58(req.AllowedProgram)
			if perr != nil {
				return zero, fmt.Errorf("allowed_program: %w", perr)
			}
			if req.Action == "add_allowed_program" {
				return auth.SessionKeysAddAllowedProgramChallenge(dwallet, pid, req.ExpectedNonce, ownerSlot), nil
			}
			return auth.SessionKeysRemoveAllowedProgramChallenge(dwallet, pid, req.ExpectedNonce, ownerSlot), nil
		case "close_session":
			if req.Recipient == "" {
				return zero, errors.New("recipient required")
			}
			rcpt, rerr := solana.PublicKeyFromBase58(req.Recipient)
			if rerr != nil {
				return zero, fmt.Errorf("recipient: %w", rerr)
			}
			return auth.SessionKeysCloseSessionChallenge(dwallet, rcpt, req.ExpectedNonce, ownerSlot), nil
		case "create_session":
			return zero, errors.New("create_session is now an init flow — POST /v1/policies/session-keys/init (Audit C2)")
		}
	}
	return zero, fmt.Errorf("unknown template/action: %s/%s", template, req.Action)
}

type adminSubmitRequest struct {
	adminChallengeRequest
	OwnerSignatureBase64      string `json:"owner_signature_base64"`
	WebauthnAuthDataBase64    string `json:"webauthn_auth_data_base64,omitempty"`
	WebauthnClientDataJSONB64 string `json:"webauthn_client_data_json_base64,omitempty"`
}

// adminSubmit accepts the off-chain owner signature for a challenge, builds
// `[precompileIx, mainIx]`, signs as gas sponsor, and sends the tx.
//
// Audit C2 (Opção 4): the request must include `init_authority_hash_base64`
// so the gateway can derive the policy PDA. Audit C1: no current_ts in the
// wire — on-chain reads from Clock sysvar.
func (s *Service) adminSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSponsor(w) {
		return
	}
	template := strings.ToLower(chi.URLParam(r, "template"))
	var req adminSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", err.Error())
		return
	}
	ownerSlot, err := decodeOwnerSlot(req.OwnerSlot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_owner_slot", err.Error())
		return
	}
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_init_authority_hash", err.Error())
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.OwnerSignatureBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_signature", "owner_signature_base64 must be valid base64")
		return
	}
	ownerSig := AdminSignature{Signature: sig}
	if req.WebauthnAuthDataBase64 != "" {
		raw, derr := base64.StdEncoding.DecodeString(req.WebauthnAuthDataBase64)
		if derr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_webauthn_auth_data", derr.Error())
			return
		}
		ownerSig.WebauthnAuthData = raw
	}
	if req.WebauthnClientDataJSONB64 != "" {
		raw, derr := base64.StdEncoding.DecodeString(req.WebauthnClientDataJSONB64)
		if derr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_webauthn_cdj", derr.Error())
			return
		}
		ownerSig.WebauthnClientDataJSON = raw
	}
	sponsor := s.GasSponsor.PublicKey()
	ctx := AdminContext{
		Dwallet:           dwallet,
		OwnerSlot:         ownerSlot,
		InitAuthorityHash: initAuthorityHash,
		Sponsor:           sponsor,
	}

	ixs, err := dispatchAdminSubmit(s.Registry, template, req, ctx, ownerSig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "build_failed", err.Error())
		return
	}
	txSig, err := s.GasSponsor.SignAndSend(r.Context(), ixs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "send_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tx_signature": txSig.String()})
}

// dispatchAdminSubmit routes admin actions to the right builder. After
// Audit C1: no `now`/`current_ts` is needed (Clock sysvar handles it).
// After Audit C2: AdminContext carries InitAuthorityHash for PDA derivation.
// After Audit H6: session-keys admin actions also need session_index.
func dispatchAdminSubmit(reg *Registry, template string, req adminSubmitRequest, ctx AdminContext, sig AdminSignature) ([]solana.Instruction, error) {
	switch template {
	case TemplateAllowlist:
		switch req.Action {
		case "add_destination", "remove_destination":
			dest, derr := decodeBase58OrBase64Bytes32(req.DestinationBase64)
			if derr != nil {
				return nil, fmt.Errorf("destination: %w", derr)
			}
			action := AllowlistAddDestination
			if req.Action == "remove_destination" {
				action = AllowlistRemoveDestination
			}
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: action, Destination: dest,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: AllowlistPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: AllowlistResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateVelocityGuard:
		switch req.Action {
		case "update_window":
			if req.MaxSigsPerWindow == nil || req.WindowSlots == nil {
				return nil, errors.New("max_sigs_per_window and window_slots required")
			}
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext:     ctx,
				Action:           VelocityUpdateWindow,
				MaxSigsPerWindow: *req.MaxSigsPerWindow,
				WindowSlots:      *req.WindowSlots,
				ExpectedNonce:    req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext: ctx, Action: VelocityPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext: ctx, Action: VelocityResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateTimeLock:
		switch req.Action {
		case "update_window":
			if req.Mode == nil || req.StartSlot == nil || req.EndSlot == nil || req.RecurringPeriodSlots == nil {
				return nil, errors.New("mode, start_slot, end_slot, recurring_period_slots required")
			}
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext:         ctx,
				Action:               TimeLockUpdateWindow,
				Mode:                 *req.Mode,
				StartSlot:            *req.StartSlot,
				EndSlot:              *req.EndSlot,
				RecurringPeriodSlots: *req.RecurringPeriodSlots,
				ExpectedNonce:        req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext: ctx, Action: TimeLockPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext: ctx, Action: TimeLockResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateOracleConditional:
		switch req.Action {
		case "update_bounds":
			if req.MinPrice == nil || req.MaxPrice == nil || req.MaxAgeSlots == nil {
				return nil, errors.New("min_price, max_price, max_age_slots required")
			}
			var maxConfBps uint16
			if req.MaxConfidenceBps != nil {
				maxConfBps = *req.MaxConfidenceBps
			}
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OracleUpdateBounds,
				MinPrice: *req.MinPrice, MaxPrice: *req.MaxPrice, MaxAgeSlots: *req.MaxAgeSlots,
				MaxConfidenceBps: maxConfBps,
				ExpectedNonce:    req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OraclePauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OracleResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplatePasskeyStepUp:
		switch req.Action {
		case "update_policy":
			if req.ThresholdAmount == nil || req.PasskeyPubkeyB64 == "" {
				return nil, errors.New("threshold_amount and passkey_pubkey_base64 required")
			}
			pkb, derr := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
			if derr != nil || len(pkb) != 33 {
				return nil, errors.New("passkey_pubkey_base64 must decode to 33 bytes")
			}
			var pk [33]byte
			copy(pk[:], pkb)
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyUpdatePolicy,
				ThresholdAmount: *req.ThresholdAmount, PasskeyPubkey: pk,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateFHEGated:
		switch req.Action {
		case "rotate_authority":
			if req.NewFHEAuthority == "" {
				return nil, errors.New("new_fhe_authority required")
			}
			fa, ferr := solana.PublicKeyFromBase58(req.NewFHEAuthority)
			if ferr != nil {
				return nil, fmt.Errorf("new_fhe_authority: %w", ferr)
			}
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedRotateAuthority, NewFHEAuthority: fa,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateSessionKeys:
		// Audit H6: session_index required to identify which session.
		if req.SessionIndex == nil {
			return nil, errors.New("session_index required for session-keys admin actions (Audit H6)")
		}
		switch req.Action {
		case "create_session":
			return nil, errors.New("create_session moved to /v1/policies/session-keys/init (Audit C2)")
		case "revoke":
			return BuildSessionKeysAdmin(reg, SessionKeysAdminInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Action:        SessionKeysRevoke,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "add_allowed_program", "remove_allowed_program":
			if req.AllowedProgram == "" {
				return nil, errors.New("allowed_program required")
			}
			pid, perr := solana.PublicKeyFromBase58(req.AllowedProgram)
			if perr != nil {
				return nil, fmt.Errorf("allowed_program: %w", perr)
			}
			action := SessionKeysAddAllowedProgram
			if req.Action == "remove_allowed_program" {
				action = SessionKeysRemoveAllowedProgram
			}
			return BuildSessionKeysAdmin(reg, SessionKeysAdminInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Action: action, ProgramID: pid,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "close_session":
			if req.Recipient == "" {
				return nil, errors.New("recipient required")
			}
			rcpt, rerr := solana.PublicKeyFromBase58(req.Recipient)
			if rerr != nil {
				return nil, fmt.Errorf("recipient: %w", rerr)
			}
			return BuildSessionKeysClose(reg, SessionKeysCloseInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Recipient:     rcpt,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	}
	return nil, fmt.Errorf("unknown template/action: %s/%s", template, req.Action)
}

// ── request_signature ──────────────────────────────────────────

type requestSignatureReq struct {
	Template            string `json:"template,omitempty"`
	DwalletAddress      string `json:"dwallet_address"`
	DwalletCurve        uint16 `json:"dwallet_curve"`
	DwalletPublicKeyB64 string `json:"dwallet_public_key_base64"`
	MessageDigestB64    string `json:"message_digest_base64"`
	MetadataDigestB64   string `json:"metadata_digest_base64"`
	UserPubkeyB64       string `json:"user_pubkey_base64"`
	SignatureScheme     uint16 `json:"signature_scheme"`
	CpiAuthorityBump    uint8  `json:"cpi_authority_bump"`
	Destination         string `json:"destination,omitempty"`

	// Audit C2 (Opção 4): client supplies init_authority_hash so the
	// gateway can derive the policy PDA. Audit C1 removed current_slot
	// and current_ts from this DTO — Clock sysvar handles them on-chain.
	InitAuthorityHashBase64 string `json:"init_authority_hash_base64"`
}

// requestSignature handles the canonical 3-template request_signature flow.
// Templates with extra accounts (oracle/passkey/session-keys/fhe-gated) are
// served via dedicated endpoints documented elsewhere in the gateway.
func (s *Service) requestSignature(w http.ResponseWriter, r *http.Request) {
	if !s.requireSponsor(w) {
		return
	}
	template := strings.ToLower(chi.URLParam(r, "template"))
	var req requestSignatureReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", err.Error())
		return
	}
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_init_authority_hash", err.Error())
		return
	}
	msg, err := decodeFixed32(req.MessageDigestB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_message_digest", err.Error())
		return
	}
	meta := [32]byte{}
	if req.MetadataDigestB64 != "" {
		meta, err = decodeFixed32(req.MetadataDigestB64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_metadata_digest", err.Error())
			return
		}
	}
	user, err := decodeFixed32(req.UserPubkeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_user_pubkey", err.Error())
		return
	}
	if req.DwalletPublicKeyB64 == "" {
		writeErr(w, http.StatusBadRequest, "missing_dwallet_public_key", "dwallet_public_key_base64 is required")
		return
	}
	dwalletPK, err := base64.StdEncoding.DecodeString(req.DwalletPublicKeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key", err.Error())
		return
	}
	switch len(dwalletPK) {
	case 32, 33, 65:
	default:
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key", "must decode to 32, 33 or 65 bytes")
		return
	}
	_, msgBump, err := MessageApprovalPDA(s.Registry.IkaProgramID, req.DwalletCurve, dwalletPK, req.SignatureScheme, msg[:], meta[:])
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pda_failed", err.Error())
		return
	}
	common := RequestSigCommon{
		Dwallet:           dwallet,
		DwalletCurve:      req.DwalletCurve,
		DwalletPublicKey:  dwalletPK,
		Sponsor:           s.GasSponsor.PublicKey(),
		InitAuthorityHash: initAuthorityHash,
		MessageDigest:     msg,
		MetaDigest:        meta,
		UserPubkey:        user,
		SignatureScheme:   req.SignatureScheme,
		CurrentTS:         time.Now().Unix(),
	}

	var ix solana.Instruction
	switch template {
	case TemplateAllowlist:
		if req.Destination == "" {
			writeErr(w, http.StatusBadRequest, "missing_destination", "destination required")
			return
		}
		destPk, derr := solana.PublicKeyFromBase58(req.Destination)
		if derr != nil {
			writeErr(w, http.StatusBadRequest, "invalid_destination", derr.Error())
			return
		}
		var destBytes [32]byte
		copy(destBytes[:], destPk.Bytes())
		ix2, berr := BuildAllowlistRequestSignature(s.Registry, AllowlistRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump, CpiAuthorityBump: req.CpiAuthorityBump, Destination: destBytes,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ix = ix2
	case TemplateVelocityGuard:
		ix2, berr := BuildVelocityRequestSignature(s.Registry, VelocityRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump, CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ix = ix2
	case TemplateTimeLock:
		ix2, berr := BuildTimeLockRequestSignature(s.Registry, TimeLockRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump, CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if berr != nil {
			writeErr(w, http.StatusServiceUnavailable, "build_failed", berr.Error())
			return
		}
		ix = ix2
	default:
		writeErr(w, http.StatusNotFound, "unknown_template",
			template+" is not supported by this endpoint (oracle / passkey / session-keys / fhe-gated have dedicated endpoints with extra args)")
		return
	}
	sig, err := s.GasSponsor.SignAndSend(r.Context(), []solana.Instruction{ix})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "send_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tx_signature": sig.String()})
}

// ── helpers ────────────────────────────────────────────────────

func decodeBase58OrBase64Bytes32(s string) ([32]byte, error) {
	var out [32]byte
	if pk, err := solana.PublicKeyFromBase58(s); err == nil {
		copy(out[:], pk.Bytes())
		return out, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, errors.New("expected 32 bytes after base64 decode")
	}
	copy(out[:], raw)
	return out, nil
}

func (s *Service) Simulate(_ context.Context) error {
	return errors.New("simulate not yet implemented")
}

func decodeFixed32(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, errors.New("missing base64 input")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, errors.New("expected 32 bytes after base64 decode")
	}
	copy(out[:], raw)
	return out, nil
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": errCode, "message": msg}})
}
