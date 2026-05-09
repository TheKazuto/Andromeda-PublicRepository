package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// GET /v1/me/balance — token balance per bucket
// =============================================================================

type meBalancePayload struct {
	UserID      string         `json:"userId"`
	Email       string         `json:"email"`
	Balance     *store.Balance `json:"balance"`
	Plan        *meBalancePlan `json:"plan,omitempty"`
	GeneratedAt time.Time      `json:"generatedAt"`
}

type meBalancePlan struct {
	Code         string `json:"code"`
	BillingCycle string `json:"billingCycle"`
	Status       string `json:"status"`
}

func (s *Server) handleMeBalance(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	bal, err := s.store.ComputeBalance(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not compute balance")
		return
	}

	out := meBalancePayload{
		UserID:      user.ID,
		Email:       user.Email,
		Balance:     bal,
		GeneratedAt: time.Now().UTC(),
	}
	if bal.Subscription != nil {
		out.Plan = &meBalancePlan{
			Code:         bal.Subscription.PlanCode,
			BillingCycle: bal.Subscription.BillingCycle,
			Status:       bal.Subscription.Status,
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, out)
}

// =============================================================================
// GET /v1/me/usage?range=30d — daily series + top routes
// =============================================================================

type meUsagePayload struct {
	UserID      string                   `json:"userId"`
	Range       string                   `json:"range"`
	Since       time.Time                `json:"since"`
	Until       time.Time                `json:"until"`
	Tokens      int64                    `json:"tokens"`
	Calls       int64                    `json:"calls"`
	Daily       []store.UsageDailyBucket `json:"daily"`
	TopRoutes   []store.UsageRouteBucket `json:"topRoutes"`
	GeneratedAt time.Time                `json:"generatedAt"`
}

func (s *Server) handleMeUsage(w http.ResponseWriter, r *http.Request) {
	userID := userIDFrom(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	rangeStr := strings.TrimSpace(r.URL.Query().Get("range"))
	if rangeStr == "" {
		rangeStr = "30d"
	}
	dur, err := parseUsageRange(rangeStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	limitStr := r.URL.Query().Get("topLimit")
	topLimit := 10
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			topLimit = n
		}
	}

	until := time.Now().UTC()
	since := until.Add(-dur)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	report, err := s.store.GetUsageReport(ctx, userID, since, until, topLimit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not load usage report")
		return
	}

	w.Header().Set("Cache-Control", "private, max-age=30")
	writeJSON(w, http.StatusOK, meUsagePayload{
		UserID:      userID,
		Range:       rangeStr,
		Since:       report.Since,
		Until:       report.Until,
		Tokens:      report.Tokens,
		Calls:       report.Calls,
		Daily:       report.Daily,
		TopRoutes:   report.TopRoutes,
		GeneratedAt: time.Now().UTC(),
	})
}

// parseUsageRange accepts shorthand (1d, 7d, 30d, 90d, 1y) or generic
// `<n>d`/`<n>h` strings. Caps at 365 days to bound the SQL load.
func parseUsageRange(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("range required")
	}
	const maxDays = 365
	switch s {
	case "1d", "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	case "90d":
		return 90 * 24 * time.Hour, nil
	case "365d", "1y":
		return maxDays * 24 * time.Hour, nil
	}
	var unit time.Duration
	var num string
	switch {
	case strings.HasSuffix(s, "d"):
		unit = 24 * time.Hour
		num = strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "h"):
		unit = time.Hour
		num = strings.TrimSuffix(s, "h")
	default:
		return 0, fmt.Errorf("range must end with 'd' or 'h' (e.g. 30d, 12h)")
	}
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid range number")
	}
	dur := time.Duration(n) * unit
	if dur > maxDays*24*time.Hour {
		dur = maxDays * 24 * time.Hour
	}
	return dur, nil
}

// =============================================================================
// PATCH /v1/me/password — change password
// =============================================================================
//
// Requires the current password to defeat hijacked-JWT scenarios. Returns
// 400 for OAuth-only users (no local password set) — they should re-auth
// via their provider rather than maintaining a local secret.

type changePasswordReq struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

const minPasswordLen = 8

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}

	var req changePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "currentPassword and newPassword are required")
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("newPassword must be at least %d characters", minPasswordLen))
		return
	}
	if req.CurrentPassword == req.NewPassword {
		writeError(w, http.StatusBadRequest, "newPassword must differ from currentPassword")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if user.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "no password set for this account; sign in with your OAuth provider")
		return
	}
	if !auth.CheckPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), uid, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	_ = s.store.RevokeRefreshTokensByUser(r.Context(), uid)
	clearRefreshCookie(w, s.cfg.Env == "production")
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// DELETE /v1/me — soft-delete (anonymize) the account
// =============================================================================
//
// Requires either the current password (password users) OR the exact
// account email (OAuth-only users) as a confirmation token. The action
// anonymizes PII, drops oauth links, and revokes all API keys. Stripe
// records, subscriptions, and historical usage are preserved for
// compliance and downstream reconciliation.

type deleteAccountReq struct {
	Password     string `json:"password"`
	ConfirmEmail string `json:"confirmEmail"`
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}

	var req deleteAccountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if user.PasswordHash != "" {
		if req.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required to delete this account")
			return
		}
		if !auth.CheckPassword(req.Password, user.PasswordHash) {
			writeError(w, http.StatusUnauthorized, "password is incorrect")
			return
		}
	} else {
		if strings.TrimSpace(req.ConfirmEmail) == "" {
			writeError(w, http.StatusBadRequest, "confirmEmail is required to delete this account")
			return
		}
		if !strings.EqualFold(strings.TrimSpace(req.ConfirmEmail), user.Email) {
			writeError(w, http.StatusUnauthorized, "confirmEmail does not match")
			return
		}
	}

	if err := s.store.SoftDeleteUser(r.Context(), uid); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
