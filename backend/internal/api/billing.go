package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/shinkalabs/andromeda-backend/internal/billing"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// POST /v1/billing/checkout — create a Stripe Checkout Session
// =============================================================================

type checkoutReq struct {
	PlanCode string `json:"planCode"`
	Cycle    string `json:"cycle"`
}

type checkoutResp struct {
	URL       string `json:"url"`
	SessionID string `json:"sessionId"`
}

func (s *Server) handleBillingCheckout(w http.ResponseWriter, r *http.Request) {
	if s.billing == nil || !s.billing.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	var req checkoutReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	plan := strings.ToLower(strings.TrimSpace(req.PlanCode))
	cycle := strings.ToLower(strings.TrimSpace(req.Cycle))
	if cycle == "" {
		cycle = "monthly"
	}
	if plan == "" {
		writeError(w, http.StatusBadRequest, "planCode required")
		return
	}
	if plan == "free" {
		writeError(w, http.StatusBadRequest, "free plan does not require checkout")
		return
	}

	// User does not yet have a Stripe customer column populated in our
	// User struct (kept lean), so we fetch the active subscription if
	// any to pull the existing Stripe customer id.
	stripeCustomerID := ""
	if sub, err := s.store.GetActiveSubscription(r.Context(), user.ID); err == nil && sub != nil {
		stripeCustomerID = sub.StripeCustomerID
	}

	res, err := s.billing.CreateCheckoutSession(r.Context(), billing.CreateCheckoutSessionInput{
		UserID:           user.ID,
		UserEmail:        user.Email,
		StripeCustomerID: stripeCustomerID,
		PlanCode:         plan,
		Cycle:            cycle,
	})
	if err != nil {
		switch {
		case errors.Is(err, billing.ErrServiceDisabled):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, billing.ErrPriceNotConfigured):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeInternal(w)
		}
		return
	}

	if res.StripeCustomerID != "" && stripeCustomerID == "" {
		if err := s.store.SetUserStripeCustomerID(r.Context(), user.ID, res.StripeCustomerID); err != nil &&
			!errors.Is(err, store.ErrAlreadyExists) {
			// Non-fatal — Stripe still completed.
			_ = err
		}
	}

	writeJSON(w, http.StatusOK, checkoutResp{URL: res.URL, SessionID: res.SessionID})
}

// =============================================================================
// POST /v1/billing/portal — Stripe Customer Portal session
// =============================================================================

type portalReq struct {
	ReturnURL string `json:"returnUrl"`
}

type portalResp struct {
	URL string `json:"url"`
}

func (s *Server) handleBillingPortal(w http.ResponseWriter, r *http.Request) {
	if s.billing == nil || !s.billing.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	sub, err := s.store.GetActiveSubscription(r.Context(), userID)
	if err != nil || sub == nil || sub.StripeCustomerID == "" {
		writeError(w, http.StatusConflict, "complete a checkout first")
		return
	}

	var req portalReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	returnURL := strings.TrimSpace(req.ReturnURL)
	if returnURL == "" && s.cfg.DashboardBaseURL != "" {
		returnURL = s.cfg.DashboardBaseURL + "/dashboard/billing"
	}

	url, err := s.billing.CreatePortalSession(r.Context(), sub.StripeCustomerID, returnURL)
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, portalResp{URL: url})
}

// =============================================================================
// POST /v1/billing/overage/{enable,disable}
// =============================================================================

func (s *Server) handleBillingOverageEnable(w http.ResponseWriter, r *http.Request) {
	if s.billing == nil || !s.billing.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	sub, err := s.store.GetActiveSubscription(r.Context(), userID)
	if err != nil || sub == nil {
		writeError(w, http.StatusForbidden, "no active subscription")
		return
	}
	if sub.StripeSubscriptionID == "" {
		writeError(w, http.StatusConflict, "subscription is not linked to Stripe")
		return
	}
	if sub.OverageEnabled {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "itemId": sub.StripeOverageItemID})
		return
	}

	tier := overageTierForPlan(sub.PlanCode)
	itemID, err := s.billing.AddOverageItem(r.Context(), sub.StripeSubscriptionID, tier)
	if err != nil {
		writeInternal(w)
		return
	}
	_ = s.store.SetSubscriptionOverageItem(r.Context(), sub.ID, itemID)
	enabled := true
	cardPresent := true
	if _, err := s.store.UpdateSubscription(r.Context(), sub.ID, store.SubscriptionMutation{
		OverageEnabled:     &enabled,
		OverageCardPresent: &cardPresent,
	}); err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "itemId": itemID})
}

func (s *Server) handleBillingOverageDisable(w http.ResponseWriter, r *http.Request) {
	if s.billing == nil || !s.billing.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	sub, err := s.store.GetActiveSubscription(r.Context(), userID)
	if err != nil || sub == nil {
		writeError(w, http.StatusForbidden, "no active subscription")
		return
	}

	if sub.StripeOverageItemID != "" {
		if err := s.billing.RemoveOverageItem(r.Context(), sub.StripeOverageItemID); err != nil {
			writeInternal(w)
			return
		}
	}
	_ = s.store.SetSubscriptionOverageItem(r.Context(), sub.ID, "")
	disabled := false
	if _, err := s.store.UpdateSubscription(r.Context(), sub.ID, store.SubscriptionMutation{
		OverageEnabled: &disabled,
	}); err != nil {
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func overageTierForPlan(planCode string) string {
	if strings.EqualFold(planCode, "enterprise") {
		return "enterprise"
	}
	return "standard"
}

// =============================================================================
// POST /v1/billing/stripe/webhook
// =============================================================================

func (s *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if s.billing == nil || !s.billing.Enabled() || s.billingWebhook == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if sig == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ev, err := s.billingWebhook.Verify(body, sig)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	first, err := s.store.MarkStripeEventProcessed(r.Context(), ev.ID, string(ev.Type), ev.APIVersion)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !first {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.billingWebhook.Handle(r.Context(), ev); err != nil {
		_ = s.store.UnmarkStripeEventProcessed(r.Context(), ev.ID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
