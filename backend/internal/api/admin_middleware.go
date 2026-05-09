package api

import (
	"context"
	"net/http"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// requireAdmin gates /admin/* endpoints. Two parallel paths are accepted:
//
//   1. Authorization: Bearer <admin_jwt>  (preferred)
//   2. X-Admin-Token: <ADMIN_TOKEN>       (legacy shared secret for CLI)
//
// JWT path attaches the admin identity to the request context via
// withAdmin, which downstream handlers use for audit logs.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Bearer JWT.
		if raw := bearerToken(r); raw != "" && s.cfg.AdminJWTSecret != "" {
			claims, err := auth.ParseAdminToken([]byte(s.cfg.AdminJWTSecret), raw)
			if err == nil {
				next.ServeHTTP(w, withAdmin(r, &adminIdentity{
					ID:    claims.AdminID,
					Email: claims.Email,
					Role:  claims.Role,
				}))
				return
			}
			// JWT present but invalid — fall through to shared-secret check.
		}
		// 2. Shared-secret fallback.
		token := r.Header.Get("X-Admin-Token")
		if token != "" && s.cfg.AdminToken != "" && auth.ConstantTimeEqual(token, s.cfg.AdminToken) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "admin token required")
	})
}

// requireAdminJWT is a stricter variant that REQUIRES the Bearer JWT path
// (no shared-secret fallback). Used for handlers that must record the
// identity of the operator (admin user CRUD, audit reads, MFA setup).
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
