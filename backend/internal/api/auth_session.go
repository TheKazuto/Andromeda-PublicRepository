package api

import (
	"context"
	"net/http"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// Session helpers — refresh-token cookie issuance, rotation, and lockout glue.
//
// Access tokens (short-lived JWTs) travel in the response body and are kept
// in dashboard memory only. Refresh tokens (long-lived, opaque random) live
// in an HttpOnly cookie scoped to /v1/auth so XSS in the dashboard cannot
// read them. Rotation is single-use: every refresh produces a new token and
// revokes the parent. Reuse of a parent triggers full-family revocation.
// =============================================================================

// refreshCookieName is the HttpOnly cookie the dashboard never sees.
const refreshCookieName = "andromeda_refresh"

// LockoutThreshold is how many consecutive failed logins trigger a lock
// for regular users.
const LockoutThreshold = 5

// LockoutDuration is how long the account stays locked after the threshold
// is crossed.
const LockoutDuration = 15 * time.Minute

// AdminLockoutThreshold is intentionally tighter — admin login + TOTP is
// the highest-impact path so we tolerate fewer failures.
const AdminLockoutThreshold = 3

// AdminLockoutDuration matches the elevated risk profile of admin sessions.
const AdminLockoutDuration = 30 * time.Minute

// issueSession persists a fresh refresh token for `user`, sets the
// HttpOnly cookie on `w`, and returns the access JWT + expiry. It is the
// canonical session-bootstrap path used by signup, login, and OAuth callback.
//
// `replacesID` should be empty for fresh sessions and set to the parent
// refresh-token id during rotation so the new row links back to the chain.
func (s *Server) issueSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, replacesID string) (string, time.Time, error) {
	tok, exp, err := auth.IssueToken(s.cfg.JWTSecret, user.ID, user.Email)
	if err != nil {
		return "", time.Time{}, err
	}
	rawRefresh, hash, err := auth.GenerateOpaqueToken()
	if err != nil {
		return "", time.Time{}, err
	}
	refreshExp := time.Now().UTC().Add(auth.RefreshTokenTTL)
	issue := store.RefreshTokenIssue{
		UserID:     user.ID,
		TokenHash:  hash,
		ExpiresAt:  refreshExp,
		UserAgent:  truncate(r.UserAgent(), 250),
		IP:         clientIP(r),
		ReplacesID: replacesID,
	}
	if replacesID != "" {
		_, err = s.store.RotateRefreshToken(ctx, replacesID, issue)
	} else {
		_, err = s.store.CreateRefreshToken(ctx, issue)
	}
	if err != nil {
		return "", time.Time{}, err
	}
	setRefreshCookie(w, rawRefresh, refreshExp, s.cfg.Env == "production")
	return tok, exp, nil
}

// setRefreshCookie installs the HttpOnly refresh cookie. SameSite=None;
// Secure is required in production because the dashboard and backend live
// on different sites; in development we relax to SameSite=Lax over plain
// HTTP so localhost flows work without TLS termination.
func setRefreshCookie(w http.ResponseWriter, raw string, expires time.Time, prod bool) {
	cookie := &http.Cookie{
		Name:     refreshCookieName,
		Value:    raw,
		Path:     "/v1/auth",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
	}
	if prod {
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
	} else {
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, cookie)
}

// clearRefreshCookie expires the cookie client-side. Used by /v1/auth/logout.
func clearRefreshCookie(w http.ResponseWriter, prod bool) {
	cookie := &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/v1/auth",
		MaxAge:   -1,
		HttpOnly: true,
	}
	if prod {
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
	} else {
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, cookie)
}

// readRefreshCookie pulls the raw refresh token out of the request cookie.
func readRefreshCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(refreshCookieName)
	if err != nil || c == nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// =============================================================================
// /v1/auth/refresh — exchange the cookie for a new access token + rotated
// cookie. Implements single-use semantics: the parent token is consumed
// inside ConsumeRefreshToken (atomic UPDATE gated on revoked_at IS NULL).
// =============================================================================

type refreshResp struct {
	Token     string      `json:"token"`
	ExpiresAt time.Time   `json:"expiresAt"`
	User      *store.User `json:"user"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	raw, ok := readRefreshCookie(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "no refresh token")
		return
	}
	hash := auth.HashOpaqueToken(raw)
	row, err := s.store.GetRefreshTokenByHash(r.Context(), hash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	if row.RevokedAt != nil {
		// Reuse of a consumed token: assume the cookie was stolen and
		// revoke every descendant before refusing the request.
		_ = s.store.RevokeRefreshTokenFamily(r.Context(), row.ID)
		clearRefreshCookie(w, s.cfg.Env == "production")
		writeError(w, http.StatusUnauthorized, "refresh token reused")
		return
	}
	if time.Now().UTC().After(row.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), row.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "user no longer exists")
		return
	}
	tok, exp, err := s.issueSession(r.Context(), w, r, user, row.ID)
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, refreshResp{Token: tok, ExpiresAt: exp, User: user})
}

// =============================================================================
// /v1/auth/logout — revoke every active refresh token for the caller and
// clear the cookie. JWT itself remains valid until natural expiry; the
// short TTL means the worst-case window is bounded by TokenTTL.
// =============================================================================

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Revoke by cookie if present — covers logged-in flows even when the
	// JWT has already expired (and therefore there is no userID in ctx).
	if raw, ok := readRefreshCookie(r); ok {
		hash := auth.HashOpaqueToken(raw)
		if row, err := s.store.GetRefreshTokenByHash(r.Context(), hash); err == nil {
			_ = s.store.RevokeRefreshTokensByUser(r.Context(), row.UserID)
		}
	}
	clearRefreshCookie(w, s.cfg.Env == "production")
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Lockout helpers used by login + admin login.
// =============================================================================

// checkLockout inspects locked_until. Returns ok=false + the unlock time
// (truncated) when the caller should be refused.
func (s *Server) checkLockout(ctx context.Context, userID string) (locked bool, until *time.Time) {
	if userID == "" {
		return false, nil
	}
	locked, until, err := s.store.IsUserLocked(ctx, userID)
	if err != nil || !locked {
		return false, nil
	}
	return true, until
}

// recordFailedLogin bumps the counter; called whenever password verification
// fails AFTER we have located the user (we never increment for unknown
// emails, otherwise an attacker could lock out arbitrary accounts by
// guessing emails).
func (s *Server) recordFailedLogin(ctx context.Context, userID string) {
	if userID == "" {
		return
	}
	_ = s.store.IncrementUserFailedLogin(ctx, userID, LockoutThreshold, LockoutDuration)
}

// recordSuccessfulLogin clears the counter on a clean login.
func (s *Server) recordSuccessfulLogin(ctx context.Context, userID string) {
	if userID == "" {
		return
	}
	_ = s.store.ResetUserFailedLogin(ctx, userID)
}

// truncate caps a string at n bytes — used to keep User-Agent strings out of
// the database from blowing up.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
