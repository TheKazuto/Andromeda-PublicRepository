package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// GET /v1/gifts/preview/{token} — public preview of a gift card
// =============================================================================
//
// Returns a sanitised projection so the dashboard can show the recipient
// what they're getting before login. The redeem token is the secret —
// 256 bits of random — so brute-force lookups are not a concern.
//
// We do NOT expose buyer email or stripe payment id in the preview.

type giftPreviewResp struct {
	PlanCode       string    `json:"planCode"`
	DurationMonths int       `json:"durationMonths"`
	Source         string    `json:"source"`
	Message        string    `json:"message,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Status         string    `json:"status"` // 'redeemable' | 'redeemed' | 'refunded' | 'expired'
}

func (s *Server) handleGiftPreview(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}
	gift, err := s.store.GetGiftCardByToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "gift card not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	status := "redeemable"
	switch {
	case gift.RedeemedAt != nil:
		status = "redeemed"
	case gift.RefundedAt != nil:
		status = "refunded"
	case !time.Now().UTC().Before(gift.ExpiresAt):
		status = "expired"
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, giftPreviewResp{
		PlanCode:       gift.PlanCode,
		DurationMonths: gift.DurationMonths,
		Source:         gift.Source,
		Message:        gift.Message,
		ExpiresAt:      gift.ExpiresAt,
		Status:         status,
	})
}

// =============================================================================
// POST /v1/gifts/redeem — apply a gift card to the authenticated user
// =============================================================================

type giftRedeemReq struct {
	Token string `json:"token"`
}

type giftRedeemResp struct {
	Action       string              `json:"action"`
	AddedTokens  int64               `json:"addedTokens"`
	AddedDays    int                 `json:"addedDays"`
	Subscription *store.Subscription `json:"subscription"`
	Gift         giftPreviewResp     `json:"gift"`
}

func (s *Server) handleGiftRedeem(w http.ResponseWriter, r *http.Request) {
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}

	var req giftRedeemReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	res, err := s.store.ApplyGiftCard(ctx, token, userID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "gift card not found")
		case errors.Is(err, store.ErrGiftAlreadyUsed):
			writeError(w, http.StatusConflict, "gift card already redeemed")
		case errors.Is(err, store.ErrGiftRefunded):
			writeError(w, http.StatusGone, "gift card was refunded by the buyer")
		case errors.Is(err, store.ErrGiftExpired):
			writeError(w, http.StatusGone, "gift card expired")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	writeJSON(w, http.StatusOK, giftRedeemResp{
		Action:       res.Action,
		AddedTokens:  res.AddedTokens,
		AddedDays:    res.AddedDays,
		Subscription: res.Subscription,
		Gift: giftPreviewResp{
			PlanCode:       res.GiftCard.PlanCode,
			DurationMonths: res.GiftCard.DurationMonths,
			Source:         res.GiftCard.Source,
			Message:        res.GiftCard.Message,
			ExpiresAt:      res.GiftCard.ExpiresAt,
			Status:         "redeemed",
		},
	})
}
