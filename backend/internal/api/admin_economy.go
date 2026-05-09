package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/billing"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// POST /admin/credits — grant a token credit to a user
// =============================================================================

type adminGrantCreditReq struct {
	UserID    string     `json:"userId"`
	Email     string     `json:"email"`
	Amount    int64      `json:"amount"`
	Reason    string     `json:"reason"`    // 'trial' | 'support' | 'promo' | 'hackathon' | 'partner'
	GrantedBy string     `json:"grantedBy"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func (s *Server) handleAdminGrantCredit(w http.ResponseWriter, r *http.Request) {
	var req adminGrantCreditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	userID, err := s.resolveUser(r.Context(), req.UserID, req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if req.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "amount must be > 0")
		return
	}
	grantedBy := strings.TrimSpace(req.GrantedBy)
	if grantedBy == "" {
		grantedBy = "admin"
	}
	in := store.CreditGrant{
		UserID:    userID,
		Amount:    req.Amount,
		Reason:    strings.ToLower(strings.TrimSpace(req.Reason)),
		GrantedBy: grantedBy,
	}
	if req.ExpiresAt != nil {
		in.ExpiresAt = *req.ExpiresAt
	}
	credit, err := s.store.GrantCredit(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"credit.granted", credit.ID, map[string]any{
				"user_id": userID,
				"amount":  in.Amount,
				"reason":  in.Reason,
			})
	}
	writeJSON(w, http.StatusCreated, credit)
}

// =============================================================================
// POST /admin/coupons — emit a promotional gift card (free, by Andromeda)
// =============================================================================

type adminCreateCouponReq struct {
	PlanCode       string     `json:"planCode"`
	DurationMonths int        `json:"durationMonths"` // 1 or 12
	GrantedBy      string     `json:"grantedBy"`
	Message        string     `json:"message"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
}

type adminCreateCouponResp struct {
	GiftCard  *store.GiftCard `json:"giftCard"`
	RedeemURL string          `json:"redeemUrl"`
}

func (s *Server) handleAdminCreateCoupon(w http.ResponseWriter, r *http.Request) {
	var req adminCreateCouponReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	planCode := strings.ToLower(strings.TrimSpace(req.PlanCode))
	if planCode == "" {
		writeError(w, http.StatusBadRequest, "planCode required")
		return
	}
	if req.DurationMonths != 1 && req.DurationMonths != 12 {
		writeError(w, http.StatusBadRequest, "durationMonths must be 1 or 12")
		return
	}
	grantedBy := strings.TrimSpace(req.GrantedBy)
	if grantedBy == "" {
		grantedBy = "admin"
	}
	plan, err := s.store.GetPlanByCode(r.Context(), planCode)
	if err != nil {
		writeError(w, http.StatusNotFound, "plan not found")
		return
	}
	if !plan.IsGiftable {
		writeError(w, http.StatusBadRequest, "plan does not allow gift cards")
		return
	}

	token, err := auth.GenerateGiftToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate redeem token")
		return
	}
	in := store.GiftCardCreate{
		RedeemToken:    token,
		PlanCode:       planCode,
		DurationMonths: req.DurationMonths,
		Source:         "promo",
		GrantedBy:      grantedBy,
		Message:        strings.TrimSpace(req.Message),
	}
	if req.ExpiresAt != nil {
		in.ExpiresAt = *req.ExpiresAt
	} else {
		in.ExpiresAt = time.Now().UTC().Add(store.GiftCardTTL)
	}

	g, err := s.store.CreateGiftCard(r.Context(), in)
	if err != nil {
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"coupon.created", g.ID, map[string]any{
				"plan_code":       g.PlanCode,
				"duration_months": g.DurationMonths,
				"source":          g.Source,
			})
	}
	writeJSON(w, http.StatusCreated, adminCreateCouponResp{
		GiftCard:  g,
		RedeemURL: redeemURL(s.cfg.DashboardBaseURL, g.RedeemToken),
	})
}

// GET /admin/coupons?source=promo&status=active
func (s *Server) handleAdminListCoupons(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	status := r.URL.Query().Get("status")
	items, err := s.store.ListGiftCardsForAdmin(r.Context(), source, status)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// POST /admin/coupons/{id}/refund
//
// Three-step flow for paid gifts:
//
//   1. Mark the local row as refunded (eligibility check + atomic flip).
//      Done first so the row state reflects intent even if Stripe is
//      flaky. ErrGiftNotEligible / ErrGiftAlreadyUsed / ErrGiftRefunded
//      are mapped to clean HTTP statuses and abort early.
//
//   2. Issue refund on Stripe via Service.RefundCheckoutPayment(sessionID)
//      — skipped for promo cards (no money). When Stripe returns
//      ErrAlreadyRefunded, treat as success.
//
//   3. If step 2 errors, the local row stays flagged (the operator can
//      still see the discrepancy in the audit log + Stripe Dashboard).
func (s *Server) handleAdminRefundCoupon(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}

	g, err := s.store.RefundGiftCard(r.Context(), id)
	switch {
	case err == nil:
		// fall through to Stripe step.
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "gift card not found")
		return
	case errors.Is(err, store.ErrGiftAlreadyUsed):
		writeError(w, http.StatusConflict, "gift card already redeemed")
		return
	case errors.Is(err, store.ErrGiftRefunded):
		writeError(w, http.StatusConflict, "gift card already refunded")
		return
	case errors.Is(err, store.ErrGiftNotEligible):
		writeError(w, http.StatusUnprocessableEntity,
			"gift card not eligible for refund (paid only, ≤7 days old, not redeemed)")
		return
	default:
		writeInternal(w)
		return
	}

	// Issue Stripe refund for paid gifts. Promo cards skip this entirely.
	stripeStatus := "skipped"
	if g.Source == "paid" && g.StripePaymentID != "" && s.billing != nil && s.billing.Enabled() {
		if err := s.billing.RefundCheckoutPayment(r.Context(), g.StripePaymentID); err != nil {
			if errors.Is(err, billing.ErrAlreadyRefunded) {
				stripeStatus = "already_refunded"
			} else {
				stripeStatus = "stripe_failed: " + err.Error()
			}
		} else {
			stripeStatus = "refunded"
		}
	}

	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"coupon.refunded", g.ID, map[string]any{
				"plan_code":      g.PlanCode,
				"source":         g.Source,
				"stripe_session": g.StripePaymentID,
				"stripe_status":  stripeStatus,
			})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"giftCard":     g,
		"stripeStatus": stripeStatus,
	})
}

// =============================================================================
// /admin/pricing-changes — schedule, list, cancel
// =============================================================================

type adminCreatePricingChangeReq struct {
	ChangeType  string    `json:"changeType"`
	TargetKey   string    `json:"targetKey"`
	NewValue    int64     `json:"newValue"`
	EffectiveAt time.Time `json:"effectiveAt"`
	CreatedBy   string    `json:"createdBy"`
	Reason      string    `json:"reason"`
}

func (s *Server) handleAdminCreatePricingChange(w http.ResponseWriter, r *http.Request) {
	var req adminCreatePricingChangeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	createdBy := strings.TrimSpace(req.CreatedBy)
	if createdBy == "" {
		if a := adminFrom(r); a != nil {
			createdBy = a.Email
		} else {
			createdBy = "admin"
		}
	}
	in := store.PricingChangeCreate{
		ChangeType:  strings.ToLower(strings.TrimSpace(req.ChangeType)),
		TargetKey:   strings.TrimSpace(req.TargetKey),
		NewValue:    req.NewValue,
		EffectiveAt: req.EffectiveAt,
		CreatedBy:   createdBy,
		Reason:      strings.TrimSpace(req.Reason),
	}
	pc, err := s.store.CreatePricingChange(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"pricing_change.scheduled", strconv.FormatInt(pc.ID, 10), map[string]any{
				"change_type":  pc.ChangeType,
				"target_key":   pc.TargetKey,
				"new_value":    pc.NewValue,
				"effective_at": pc.EffectiveAt,
			})
	}
	writeJSON(w, http.StatusCreated, pc)
}

// GET /admin/pricing-changes?status=pending  (default)
// GET /admin/pricing-changes?status=by-target&type=plan_price&target=pro
func (s *Server) handleAdminListPricingChanges(w http.ResponseWriter, r *http.Request) {
	status := strings.ToLower(r.URL.Query().Get("status"))
	if status == "" {
		status = "pending"
	}
	switch status {
	case "pending":
		items, err := s.store.ListPendingPricingChanges(r.Context())
		if err != nil {
			writeInternal(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	case "by-target":
		changeType := r.URL.Query().Get("type")
		target := r.URL.Query().Get("target")
		if changeType == "" || target == "" {
			writeError(w, http.StatusBadRequest,
				"status=by-target requires ?type=<change_type>&target=<key>")
			return
		}
		items, err := s.store.ListPricingChangesByTarget(r.Context(), changeType, target)
		if err != nil {
			writeInternal(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	default:
		writeError(w, http.StatusBadRequest, "status must be 'pending' or 'by-target'")
	}
}

// DELETE /admin/pricing-changes/{id}
func (s *Server) handleAdminCancelPricingChange(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be an integer")
		return
	}
	if err := s.store.CancelPricingChange(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "pricing change not found")
		case errors.Is(err, store.ErrPricingChangeBusy):
			writeError(w, http.StatusConflict, "change has already been applied or cancelled")
		default:
			writeInternal(w)
		}
		return
	}
	if a := adminFrom(r); a != nil {
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"pricing_change.cancelled", strconv.FormatInt(id, 10), nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// PATCH /admin/subscriptions/{id}/overage — toggle overage on/off
// =============================================================================

type adminUpdateOverageReq struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	CardPresent *bool  `json:"cardPresent,omitempty"`
	CapTokens   *int64 `json:"capTokens,omitempty"`
}

func (s *Server) handleAdminUpdateOverage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	var req adminUpdateOverageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	mut := store.SubscriptionMutation{
		OverageEnabled:     req.Enabled,
		OverageCardPresent: req.CardPresent,
		OverageCapTokens:   req.CapTokens,
	}
	sub, err := s.store.UpdateSubscription(r.Context(), id, mut)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		writeInternal(w)
		return
	}
	if a := adminFrom(r); a != nil {
		payload := map[string]any{}
		if req.Enabled != nil {
			payload["enabled"] = *req.Enabled
		}
		if req.CardPresent != nil {
			payload["card_present"] = *req.CardPresent
		}
		if req.CapTokens != nil {
			payload["cap_tokens"] = *req.CapTokens
		}
		s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
			"subscription.overage_updated", id, payload)
	}
	writeJSON(w, http.StatusOK, sub)
}
