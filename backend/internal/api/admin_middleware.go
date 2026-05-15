package api

import (
	"context"
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
