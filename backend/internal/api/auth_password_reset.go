package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/notifications"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// /v1/auth/forgot-password
//
// Anti-enumeration: ALWAYS returns 200 OK regardless of whether the email
// matches a user. Token + email send happen asynchronously so the response
// time stays constant. The dashboard message is intentionally non-committal
// ("if an account exists, a reset link has been sent").
// =============================================================================

type forgotPasswordReq struct {
	Email string `json:"email"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Even on parse error we return 200 to avoid signalling state to a
		// probing attacker. We still want a 400 in case the body is empty —
		// keep this surface narrow.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	// Always respond 200 — the work that follows is best-effort.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	if email == "" {
		return
	}

	// Detach from the request context so a slow SMTP path does not block
	// the response (which has already been flushed).
	go s.dispatchPasswordReset(email)
}

func (s *Server) dispatchPasswordReset(email string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil || user == nil || user.PasswordHash == "" {
		// No-op for unknown emails OR OAuth-only accounts: the latter must
		// re-auth via their provider, sending them a reset link is misleading.
		return
	}
	raw, hash, err := auth.GenerateOpaqueToken()
	if err != nil {
		slog.Default().Warn("forgot-password: token generation failed", "err", err)
		return
	}
	if err := s.store.CreatePasswordResetToken(ctx, store.PasswordResetIssue{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(auth.PasswordResetTTL),
	}); err != nil {
		slog.Default().Warn("forgot-password: token persist failed", "err", err)
		return
	}

	resetURL := s.passwordResetURL(raw)
	if s.mailer == nil {
		slog.Default().Info("forgot-password: SMTP unavailable; reset link discarded", "user_id", user.ID)
		return
	}
	from := s.cfg.SMTPFrom
	if from == "" {
		from = "Andromeda <noreply@shinkalabs.com>"
	}
	msg := notifications.Message{
		From:      from,
		To:        user.Email,
		Subject:   "Reset your Andromeda password",
		PlainBody: passwordResetPlain(user.Name, resetURL),
		HTMLBody:  passwordResetHTML(user.Name, resetURL),
	}
	if err := s.mailer.Send(msg); err != nil {
		slog.Default().Warn("forgot-password: mailer send failed", "err", err, "user_id", user.ID)
	}
}

// passwordResetURL builds the user-facing link the email points at. The
// dashboard `/auth/reset` page is responsible for rendering the form and
// POSTing back to /v1/auth/reset-password.
func (s *Server) passwordResetURL(rawToken string) string {
	base := strings.TrimRight(s.cfg.OAuth.DashboardURL, "/")
	if base == "" {
		base = strings.TrimRight(s.cfg.DashboardBaseURL, "/")
	}
	if base == "" {
		base = "http://localhost:3000"
	}
	return base + "/auth/reset?token=" + rawToken
}

func passwordResetPlain(name, url string) string {
	greet := "Hi"
	if strings.TrimSpace(name) != "" {
		greet = "Hi " + name
	}
	return fmt.Sprintf(`%s,

We received a request to reset your Andromeda password. To choose a new password,
follow the link below within the next 30 minutes:

%s

If you did not request this, you can ignore this email — your password will not change.

— Andromeda
`, greet, url)
}

func passwordResetHTML(name, url string) string {
	greet := "Hi"
	if strings.TrimSpace(name) != "" {
		greet = "Hi " + name
	}
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family:sans-serif;line-height:1.5">
<p>%s,</p>
<p>We received a request to reset your Andromeda password. To choose a new password,
click the link below within the next 30 minutes:</p>
<p><a href="%s">Reset my password</a></p>
<p>If you did not request this, you can ignore this email — your password will not change.</p>
<p>— Andromeda</p>
</body></html>`, greet, url)
}

// =============================================================================
// /v1/auth/reset-password
//
// Single-use atomic: ConsumePasswordResetToken does the entire validation
// (existence + expiry + not-already-used) inside the same UPDATE that
// marks it used, so two concurrent requests cannot both reset.
// =============================================================================

type resetPasswordReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		writeError(w, http.StatusBadRequest, "newPassword must be at least 8 characters")
		return
	}

	hash := auth.HashOpaqueToken(req.Token)
	userID, err := s.store.ConsumePasswordResetToken(r.Context(), hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "token is invalid or has expired")
			return
		}
		writeInternal(w)
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeInternal(w)
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), userID, newHash); err != nil {
		writeInternal(w)
		return
	}
	// Sign the user out everywhere — a password reset is a strong signal
	// that previously-issued sessions should not survive.
	_ = s.store.RevokeRefreshTokensByUser(r.Context(), userID)
	// Also clear any lockout — the user just proved control of the email.
	_ = s.store.ResetUserFailedLogin(r.Context(), userID)

	w.WriteHeader(http.StatusNoContent)
}
