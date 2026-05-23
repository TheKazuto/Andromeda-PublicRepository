package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// requireAdminJWT gates /admin/* endpoints: it REQUIRES the Bearer JWT
// path (no shared-secret fallback) and attaches the admin identity to
// the request context via withAdmin so downstream handlers can record
// the operator in audit logs.
func (s *Server) requireAdminJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminJWTSecret == "" {
			writeError(w, http.StatusServiceUnavailable, "admin JWT auth not configured")
			return
		}
		raw := bearerToken(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "Authorization: Bearer <admin_jwt> required")
			return
		}
		claims, err := auth.ParseAdminToken([]byte(s.cfg.AdminJWTSecret), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid admin JWT")
			return
		}
		next.ServeHTTP(w, withAdmin(r, &adminIdentity{
			ID:    claims.AdminID,
			Email: claims.Email,
			Role:  claims.Role,
		}))
	})
}

// requireMetricsToken gates GET /metrics. The backend has a public domain
// (auth.andromedainfra.pro) because the static dashboard calls it from the
// browser, so /metrics is NOT on a private network — leaving it open leaks
// DB pool stats, per-route request counters and rate-limit blocks, which are
// useful for attack reconnaissance.
//
// Auth is a shared bearer secret (ADMIN_TOKEN) so a Prometheus scraper can
// pass it without an interactive login. Behaviour:
//   - ADMIN_TOKEN set  → require an exact, constant-time match.
//   - ADMIN_TOKEN empty in production → 404 (metrics disabled — never open on
//     a public surface).
//   - ADMIN_TOKEN empty in development → allowed, with a startup-style warning
//     so the gap is visible. No silent fallback.
func (s *Server) requireMetricsToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			if s.cfg.Env == "production" {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			slog.Warn("/metrics is unauthenticated (ADMIN_TOKEN unset); set ADMIN_TOKEN to gate it in production")
			next.ServeHTTP(w, r)
			return
		}
		if raw := bearerToken(r); raw == "" || !auth.ConstantTimeEqual(raw, s.cfg.AdminToken) {
			writeError(w, http.StatusUnauthorized, "Authorization: Bearer <ADMIN_TOKEN> required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminAuditAppend is a non-fatal helper used by admin handlers to log
// operator actions. Failures are logged but never block the response.
// When the request was authenticated via the legacy X-Admin-Token (no
// adminFrom), the audit entry is skipped — admin identity is mandatory
// for the admin_audit_log FK.
func (s *Server) adminAuditAppend(ctx context.Context, who *store.AdminUser, r *http.Request, action, target string, payload map[string]any) {
	if who == nil || who.ID == "" {
		return
	}
	in := store.AdminAuditAppend{
		AdminID:    who.ID,
		AdminEmail: who.Email,
		Action:     action,
		Target:     target,
		Payload:    payload,
		IPAddress:  clientIP(r),
		UserAgent:  r.UserAgent(),
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = s.store.AppendAdminAudit(c, in)
}
