package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-backend/internal/apikeys"
	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// /admin/users — create users (also accepts existing email idempotently)
// =============================================================================

type adminCreateUserReq struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req adminCreateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if _, err := mail.ParseAddress(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, "invalid email")
		return
	}
	if req.Name == "" {
		req.Name = strings.SplitN(req.Email, "@", 2)[0]
	}
	u := &store.User{
		ID:        uuid.NewString(),
		Email:     req.Email,
		Name:      req.Name,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			existing, gerr := s.store.GetUserByEmail(r.Context(), req.Email)
			if gerr == nil {
				writeJSON(w, http.StatusOK, existing)
				return
			}
		}
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// =============================================================================
// /admin/api-keys — mint a key on behalf of a user
// =============================================================================

type adminCreateKeyReq struct {
	UserID string   `json:"userId"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type adminCreateKeyResp struct {
	Key  string        `json:"key"` // shown ONCE
	Item *store.APIKey `json:"item"`
}

func (s *Server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	var req adminCreateKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	userID, err := s.resolveUser(r.Context(), req.UserID, req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Untitled key"
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = append([]string{}, auth.DefaultScopes...)
	}
	if invalid := auth.ValidateScopes(scopes); invalid != "" {
		writeError(w, http.StatusBadRequest,
			"unknown scope: "+invalid+" — allowed: read, write, admin, *")
		return
	}

	full, prefix, hashed, err := apikeys.Generate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate key")
		return
	}
	item := &store.APIKey{
		ID:        uuid.NewString(),
		UserID:    userID,
		Name:      name,
		Prefix:    prefix,
		HashedKey: hashed,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateAPIKey(r.Context(), item); err != nil {
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"api_key.created", item.ID, map[string]any{
				"user_id": item.UserID,
				"name":    item.Name,
				"prefix":  item.Prefix,
				"scopes":  item.Scopes,
			})
	}
	writeJSON(w, http.StatusCreated, adminCreateKeyResp{Key: full, Item: item})
}

func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userId")
	keys, err := s.store.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

type adminUpdateKeyReq struct {
	Name           *string   `json:"name,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	IPAllowlist    *[]string `json:"ipAllowlist,omitempty"`
	AllowedOrigins *[]string `json:"allowedOrigins,omitempty"`
}

func (s *Server) handleAdminUpdateKey(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userId")
	keyID := chi.URLParam(r, "id")
	var req adminUpdateKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Scopes != nil {
		if invalid := auth.ValidateScopes(req.Scopes); invalid != "" {
			writeError(w, http.StatusBadRequest,
				"unknown scope: "+invalid+" — allowed: read, write, admin, *")
			return
		}
	}
	if req.IPAllowlist != nil {
		if invalid := auth.ValidateIPAllowlist(*req.IPAllowlist); invalid != "" {
			writeError(w, http.StatusBadRequest,
				"invalid IP / CIDR entry: "+invalid)
			return
		}
	}
	if req.AllowedOrigins != nil {
		if invalid := auth.ValidateOriginAllowlist(*req.AllowedOrigins); invalid != "" {
			writeError(w, http.StatusBadRequest,
				"invalid origin entry: "+invalid+" — origins must be of the form scheme://host[:port]")
			return
		}
	}
	mut := store.APIKeyMutation{
		Name:           req.Name,
		Scopes:         req.Scopes,
		IPAllowlist:    req.IPAllowlist,
		AllowedOrigins: req.AllowedOrigins,
	}
	updated, err := s.store.UpdateAPIKey(r.Context(), userID, keyID, mut)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "api key not found")
			return
		}
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"api_key.updated", keyID, map[string]any{
				"user_id":         userID,
				"scopes":          updated.Scopes,
				"ip_allowlist":    updated.IPAllowlist,
				"allowed_origins": updated.AllowedOrigins,
			})
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userId")
	keyID := chi.URLParam(r, "id")
	if err := s.store.RevokeAPIKey(r.Context(), userID, keyID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"api_key.revoked", keyID, map[string]any{"user_id": userID})
	}
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// /admin/subscriptions — assign plan, read sub, toggle overage
// =============================================================================

type adminAssignPlanReq struct {
	UserID   string `json:"userId"`
	Email    string `json:"email"`
	PlanCode string `json:"planCode"`
}

func (s *Server) handleAdminAssignPlan(w http.ResponseWriter, r *http.Request) {
	var req adminAssignPlanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	userID, err := s.resolveUser(r.Context(), req.UserID, req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if req.PlanCode == "" {
		writeError(w, http.StatusBadRequest, "planCode required")
		return
	}
	planCode := strings.ToLower(strings.TrimSpace(req.PlanCode))
	sub, err := s.store.AssignPlan(r.Context(), userID, planCode)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "plan not found or inactive")
			return
		}
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"subscription.assigned", sub.ID, map[string]any{
				"user_id":   userID,
				"plan_code": planCode,
			})
	}
	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleAdminGetSubscription(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userId")
	sub, err := s.store.GetActiveSubscription(r.Context(), userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no active subscription")
			return
		}
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

// =============================================================================
// /admin/plans — list and update plans
// =============================================================================

func (s *Server) handleAdminListPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.store.ListPlans(r.Context())
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": plans})
}

type adminUpdatePlanReq struct {
	Name              *string        `json:"name,omitempty"`
	MonthlyTokens     *int64         `json:"monthlyTokens,omitempty"`
	PriceCents        *int           `json:"priceCents,omitempty"`
	AnnualPriceCents  *int           `json:"annualPriceCents,omitempty"`
	OveragePer1kCents *int           `json:"overagePer1kCents,omitempty"`
	RateLimitRPS      *int           `json:"rateLimitRps,omitempty"`
	RateLimitBurst    *int           `json:"rateLimitBurst,omitempty"`
	ReadRPS           *int           `json:"readRps,omitempty"`
	ReadBurst         *int           `json:"readBurst,omitempty"`
	TxRPS             *int           `json:"txRps,omitempty"`
	TxBurst           *int           `json:"txBurst,omitempty"`
	Features          map[string]any `json:"features,omitempty"`
	IsActive          *bool          `json:"isActive,omitempty"`
	IsGiftable        *bool          `json:"isGiftable,omitempty"`
	SortOrder         *int           `json:"sortOrder,omitempty"`
}

func (s *Server) handleAdminUpdatePlan(w http.ResponseWriter, r *http.Request) {
	code := strings.ToLower(chi.URLParam(r, "code"))
	var req adminUpdatePlanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	mut := store.PlanMutation{
		Name:              req.Name,
		MonthlyTokens:     req.MonthlyTokens,
		PriceCents:        req.PriceCents,
		AnnualPriceCents:  req.AnnualPriceCents,
		OveragePer1kCents: req.OveragePer1kCents,
		RateLimitRPS:      req.RateLimitRPS,
		RateLimitBurst:    req.RateLimitBurst,
		ReadRPS:           req.ReadRPS,
		ReadBurst:         req.ReadBurst,
		TxRPS:             req.TxRPS,
		TxBurst:           req.TxBurst,
		Features:          req.Features,
		IsActive:          req.IsActive,
		IsGiftable:        req.IsGiftable,
		SortOrder:         req.SortOrder,
	}
	plan, err := s.store.UpdatePlan(r.Context(), code, mut)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "plan not found")
			return
		}
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"plan.updated", plan.Code, nil)
	}
	writeJSON(w, http.StatusOK, plan)
}

// =============================================================================
// /admin/request-costs — list + upsert
// =============================================================================

type adminUpsertCostReq struct {
	CostTokens  int    `json:"costTokens"`
	Description string `json:"description"`
}

func (s *Server) handleAdminListCosts(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRequestCosts(r.Context())
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAdminUpsertCost(w http.ResponseWriter, r *http.Request) {
	routeKey := strings.TrimSpace(chi.URLParam(r, "routeKey"))
	if routeKey == "" {
		writeError(w, http.StatusBadRequest, "routeKey required")
		return
	}
	var req adminUpsertCostReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.CostTokens < 1 {
		writeError(w, http.StatusBadRequest, "costTokens must be >= 1")
		return
	}
	c := store.RequestCost{
		RouteKey:    routeKey,
		CostTokens:  req.CostTokens,
		Description: req.Description,
	}
	if err := s.store.UpsertRequestCost(r.Context(), c); err != nil {
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"request_cost.upserted", routeKey, map[string]any{
				"cost_tokens": c.CostTokens,
			})
	}
	writeJSON(w, http.StatusOK, c)
}

// =============================================================================
// helpers
// =============================================================================

// resolveUser turns either a userId or email into a userId. Empty result
// returns ErrNotFound.
func (s *Server) resolveUser(ctx context.Context, userID, email string) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID != "" {
		return userID, nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", store.ErrNotFound
	}
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

// redeemURL builds the full URL the buyer shares with the recipient.
// The dashboard surfaces /redeem?token=<token>. When DashboardBaseURL
// is empty, returns the path only.
func redeemURL(baseURL, token string) string {
	suffix := "/redeem?token=" + token
	if baseURL == "" {
		return suffix
	}
	return strings.TrimRight(baseURL, "/") + suffix
}
