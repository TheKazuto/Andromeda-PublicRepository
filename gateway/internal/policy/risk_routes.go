package policy

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// mountRiskRoutes registers RT2 risk configuration CRUD endpoints under /v1/policy/risk/*.
// All endpoints require that the caller's dWallet belongs to the tenant they are
// manipulating config for (validated via dWallet→tenant ownership).
func (s *Service) mountRiskRoutes(r chi.Router) {
	// Risk evaluation (read-only advisory, optional per-endpoint).
	r.Post("/v1/policy/risk/evaluate", s.evaluateRisk)

	// dWallet per-dWallet risk configuration
	r.Get("/v1/policy/risk/config/{dwalletAddress}", s.getRiskConfig)
	r.Put("/v1/policy/risk/config/{dwalletAddress}", s.updateRiskConfig)
	r.Delete("/v1/policy/risk/config/{dwalletAddress}", s.deleteRiskConfig)

	// Tenant default risk policy
	r.Get("/v1/policy/risk/defaults", s.getTenantDefaults)
	r.Put("/v1/policy/risk/defaults", s.updateTenantDefaults)

	// Destination denylist (per-tenant)
	r.Post("/v1/policy/risk/denylist", s.addToDenylist)
	r.Delete("/v1/policy/risk/denylist/{destination}", s.removeFromDenylist)

	// Destination allowlist (per-tenant)
	r.Post("/v1/policy/risk/allowlist", s.addToAllowlist)
	r.Delete("/v1/policy/risk/allowlist/{destination}", s.removeFromAllowlist)
}

// --- Request/Response DTOs for risk evaluation ---

type riskEvaluateRequest struct {
	DwalletAddress   string `json:"dwallet_address,omitempty" validate:"omitempty,solana_pubkey"`
	DestinationHex   string `json:"destination_hex,omitempty" validate:"omitempty,hex_len=32"`
	RawTransaction   string `json:"raw_transaction,omitempty" validate:"omitempty,base64"`
	ChainID          string `json:"chain_id,omitempty"`
	MessageDigestHex string `json:"message_digest_hex,omitempty" validate:"omitempty,hex_len=32"`
	// RPCURL is the destination-chain RPC the dev funds (we don't host RPCs).
	// Required to run a real EVM simulation; SSRF is validated in the ika-backend.
	RPCURL string `json:"rpc_url,omitempty" validate:"omitempty,url"`
}

type riskEvaluateResponse struct {
	Risk           *riskAdvisory   `json:"risk,omitempty"`            // optional risk level + reasons
	Simulation     json.RawMessage `json:"simulation,omitempty"`      // optional simulation result (passthrough)
	DigestVerified bool            `json:"digest_verified,omitempty"` // whether digest was verified
}

// --- Request/Response DTOs for risk configuration ---

type riskConfigRequest struct {
	TenantID          string `json:"tenant_id" validate:"required"`
	WarnLevel         string `json:"warn_level" validate:"required,oneof=none low medium high critical"`
	SimulationEnabled bool   `json:"simulation_enabled,omitempty"`
}

type tenantDefaultsRequest struct {
	WarnLevel string `json:"warn_level" validate:"required,oneof=none low medium high critical"`
}

type denylistRequest struct {
	Destination string `json:"destination" validate:"required"`
	Reason      string `json:"reason,omitempty"`
}

type allowlistRequest struct {
	Destination string `json:"destination" validate:"required"`
	Reason      string `json:"reason,omitempty"`
}

// --- Risk evaluation (read-only advisory) ---

// evaluateRisk evaluates transaction risk and returns advisory information.
// POST /v1/policy/risk/evaluate
// All fields in the request are optional — the dev provides what they have.
// When the Risk Layer is configured, evaluation is advisory and best-effort:
// it ALWAYS returns HTTP 200 with a (possibly empty) advisory and never blocks.
// The only non-200 here is 503 when the feature itself is not wired
// (riskService == nil) — i.e. "advisory unavailable", not "request rejected".
func (s *Service) evaluateRisk(w http.ResponseWriter, r *http.Request) {
	if s.riskService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_unavailable",
			"risk service not configured")
		return
	}

	var req riskEvaluateRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}

	// Parse optional dWallet (default zero key if not provided).
	var dwallet solana.PublicKey
	if req.DwalletAddress != "" {
		var err error
		dwallet, err = solana.PublicKeyFromBase58(req.DwalletAddress)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "dwallet_address must be valid base58")
			return
		}
	}

	// Call the shared evaluateRiskAdvisory helper (best-effort; errors logged, not returned).
	// Handles optional rawTransaction, chainID, messageDigest for digest verification.
	advisory, simulation, digestVerified := s.evaluateRiskAdvisory(
		r.Context(), r,
		req.RawTransaction, req.ChainID, req.DestinationHex, req.MessageDigestHex, req.RPCURL,
		dwallet,
	)

	// HTTP 200 always (advisory-only).
	httpx.WriteJSON(w, http.StatusOK, riskEvaluateResponse{
		Risk:           advisory,
		Simulation:     simulation,
		DigestVerified: digestVerified,
	})
}

// --- dWallet risk configuration endpoints ---

// getRiskConfig fetches the risk configuration for a specific dWallet.
// GET /v1/policy/risk/config/{dwalletAddress}
func (s *Service) getRiskConfig(w http.ResponseWriter, r *http.Request) {
	dwalletAddress := chi.URLParam(r, "dwalletAddress")
	if dwalletAddress == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "dwalletAddress required")
		return
	}

	// Resolve the caller's tenant and enforce dWallet→tenant ownership here:
	// the config row carries the owning tenant_id, so a config that does not
	// belong to the caller is reported as 404 (indistinguishable from "does
	// not exist" — never leak another tenant's config or its existence).
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	cfg, err := s.riskConfigService.GetDWalletConfig(r.Context(), dwalletAddress)
	if err != nil {
		slog.Error("get risk config failed", "dwallet", dwalletAddress, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "config_fetch_failed", "failed to fetch configuration")
		return
	}

	if cfg == nil || cfg.TenantID != tenantID {
		httpx.WriteError(w, http.StatusNotFound, "config_not_found", "no configuration for this dWallet")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// updateRiskConfig creates or updates the risk configuration for a dWallet.
// PUT /v1/policy/risk/config/{dwalletAddress}
func (s *Service) updateRiskConfig(w http.ResponseWriter, r *http.Request) {
	dwalletAddress := chi.URLParam(r, "dwalletAddress")
	if dwalletAddress == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "dwalletAddress required")
		return
	}

	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	var req riskConfigRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}

	// Verify tenant ownership: the request's tenantID must match the caller's context.
	if req.TenantID != tenantID {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "cannot update config for a different tenant")
		return
	}

	cfg, err := s.riskConfigService.UpsertDWalletConfig(
		r.Context(),
		dwalletAddress,
		req.TenantID,
		req.WarnLevel,
		req.SimulationEnabled,
	)
	if err != nil {
		slog.Error("upsert risk config failed", "dwallet", dwalletAddress, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "config_update_failed", "failed to update configuration")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// deleteRiskConfig removes the risk configuration for a dWallet.
// DELETE /v1/policy/risk/config/{dwalletAddress}
func (s *Service) deleteRiskConfig(w http.ResponseWriter, r *http.Request) {
	dwalletAddress := chi.URLParam(r, "dwalletAddress")
	if dwalletAddress == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "dwalletAddress required")
		return
	}

	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	// Tenant-scoped delete (deny-by-default): the store filters by tenant_id,
	// so a caller can only remove its own config — a cross-tenant delete is a
	// no-op rather than wiping another tenant's row.
	if err := s.riskConfigService.DeleteDWalletConfig(r.Context(), dwalletAddress, tenantID); err != nil {
		slog.Error("delete risk config failed", "dwallet", dwalletAddress, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "config_delete_failed", "failed to delete configuration")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Tenant default risk policy endpoints ---

// getTenantDefaults fetches the default risk policy for the caller's tenant.
// GET /v1/policy/risk/defaults
func (s *Service) getTenantDefaults(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	defaults, err := s.riskConfigService.GetTenantDefaults(r.Context(), tenantID)
	if err != nil {
		slog.Error("get tenant defaults failed", "tenant", tenantID, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "defaults_fetch_failed", "failed to fetch defaults")
		return
	}

	if defaults == nil {
		httpx.WriteError(w, http.StatusNotFound, "defaults_not_found", "no defaults configured for this tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, defaults)
}

// updateTenantDefaults creates or updates the default risk policy for the caller's tenant.
// PUT /v1/policy/risk/defaults
func (s *Service) updateTenantDefaults(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	var req tenantDefaultsRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}

	defaults, err := s.riskConfigService.UpsertTenantDefaults(
		r.Context(),
		tenantID,
		req.WarnLevel,
	)
	if err != nil {
		slog.Error("upsert tenant defaults failed", "tenant", tenantID, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "defaults_update_failed", "failed to update defaults")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, defaults)
}

// --- Destination denylist endpoints ---

// addToDenylist adds a destination to the caller's tenant denylist.
// POST /v1/policy/risk/denylist
func (s *Service) addToDenylist(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	var req denylistRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}

	if req.Destination == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "destination required")
		return
	}

	if err := s.riskConfigService.AddToDenylist(r.Context(), tenantID, req.Destination, req.Reason); err != nil {
		slog.Error("add to denylist failed", "tenant", tenantID, "destination", req.Destination, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "denylist_add_failed", "failed to add to denylist")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// removeFromDenylist removes a destination from the caller's tenant denylist.
// DELETE /v1/policy/risk/denylist/{destination}
func (s *Service) removeFromDenylist(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	destination := chi.URLParam(r, "destination")
	if destination == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "destination required")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	if err := s.riskConfigService.RemoveFromDenylist(r.Context(), tenantID, destination); err != nil {
		slog.Error("remove from denylist failed", "tenant", tenantID, "destination", destination, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "denylist_remove_failed", "failed to remove from denylist")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Destination allowlist endpoints ---

// addToAllowlist adds a destination to the caller's tenant allowlist.
// POST /v1/policy/risk/allowlist
func (s *Service) addToAllowlist(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	var req allowlistRequest
	if !httpx.BindAndValidate(w, r, &req, 8<<10) {
		return
	}

	if req.Destination == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "destination required")
		return
	}

	if err := s.riskConfigService.AddToAllowlist(r.Context(), tenantID, req.Destination, req.Reason); err != nil {
		slog.Error("add to allowlist failed", "tenant", tenantID, "destination", req.Destination, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "allowlist_add_failed", "failed to add to allowlist")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// removeFromAllowlist removes a destination from the caller's tenant allowlist.
// DELETE /v1/policy/risk/allowlist/{destination}
func (s *Service) removeFromAllowlist(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.resolveTenantID(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "tenant_id not in context")
		return
	}

	destination := chi.URLParam(r, "destination")
	if destination == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "destination required")
		return
	}

	if s.riskConfigService == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "risk_disabled", "risk service not configured")
		return
	}

	if err := s.riskConfigService.RemoveFromAllowlist(r.Context(), tenantID, destination); err != nil {
		slog.Error("remove from allowlist failed", "tenant", tenantID, "destination", destination, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "allowlist_remove_failed", "failed to remove from allowlist")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Helper functions ---

// resolveTenantID safely extracts the tenant ID from the request context.
// Returns the tenant ID and true if present, or empty string and false if missing.
// Uses the pluggable tenantResolver callback (typically API key ID) if wired.
// This avoids unsafe type assertions and handles missing/invalid context gracefully.
func (s *Service) resolveTenantID(r *http.Request) (string, bool) {
	// Use the wired tenant resolver callback if available.
	if s.tenantResolver != nil {
		tenantID, err := s.tenantResolver(r)
		if err == nil && tenantID != "" {
			return tenantID, true
		}
	}
	return "", false
}
