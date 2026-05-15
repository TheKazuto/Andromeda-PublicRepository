package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// =============================================================================
// POST /admin/auth/login — exchange email + password (+ TOTP) for a JWT
// =============================================================================

type adminLoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// Optional 6-digit TOTP. Required when the admin has mfa_required=true.
	TOTPCode string `json:"totpCode,omitempty"`
}

type adminLoginResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Admin     adminMe   `json:"admin"`
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminJWTSecret == "" {
		writeError(w, http.StatusServiceUnavailable,
			"admin JWT auth not configured (ADMIN_JWT_SECRET missing)")
		return
	}
	var req adminLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	pass := req.Password
	if email == "" || pass == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	admin, err := s.store.GetAdminUserByEmail(ctx, email)
	if err != nil {
		// Constant-friendly response: do NOT distinguish unknown email vs
		// wrong password. Same status, same body.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Lockout pre-check. Admin TOTP brute-force is the highest-impact path,
	// so the threshold is intentionally tighter than the customer-side one
	// (3 vs 5) and the lock duration is longer (30 min vs 15 min).
	if locked, until, _ := s.store.IsAdminLocked(ctx, admin.ID); locked {
		w.Header().Set("Retry-After", retryAfter(until))
		writeError(w, http.StatusTooManyRequests, "admin account temporarily locked, please retry later")
		return
	}

	if err := auth.VerifyAdminPassword(pass, admin.HashedPassword); err != nil {
		if incErr := s.store.IncrementAdminFailedLogin(ctx, admin.ID, AdminLockoutThreshold, AdminLockoutDuration); incErr != nil {
			slog.Default().Warn("admin login: increment failed login failed",
				"admin_id", admin.ID, "err", incErr)
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if admin.MFARequired || admin.MFASecret != "" {
		if req.TOTPCode == "" {
			writeError(w, http.StatusUnauthorized,
				"two-factor authentication code required")
			return
		}
		lastWindow, lwErr := s.store.GetAdminTOTPLastWindow(ctx, admin.ID)
		if lwErr != nil && !errors.Is(lwErr, store.ErrNotFound) {
			slog.Default().Warn("admin login: totp last window lookup failed",
				"admin_id", admin.ID, "err", lwErr)
		}
		window, err := auth.VerifyTOTP(admin.MFASecret, req.TOTPCode, lastWindow)
		if err != nil {
			if incErr := s.store.IncrementAdminFailedLogin(ctx, admin.ID, AdminLockoutThreshold, AdminLockoutDuration); incErr != nil {
				slog.Default().Warn("admin login: increment failed login failed",
					"admin_id", admin.ID, "err", incErr)
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		// Burn this window so the same code cannot be reused.
		if setErr := s.store.SetAdminTOTPLastWindow(ctx, admin.ID, window); setErr != nil {
			// Concurrent login already burned this window — treat as replay.
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	}

	if err := s.store.ResetAdminFailedLogin(ctx, admin.ID); err != nil {
		slog.Default().Warn("admin login: reset failed login failed",
			"admin_id", admin.ID, "err", err)
	}

	tok, exp, err := auth.IssueAdminToken([]byte(s.cfg.AdminJWTSecret),
		admin.ID, admin.Email, admin.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	ip := clientIP(r)
	if err := s.store.TouchAdminLogin(ctx, admin.ID, ip); err != nil {
		slog.Default().Warn("admin login: touch last_login_at failed",
			"admin_id", admin.ID, "err", err)
	}

	s.adminAuditAppend(ctx, admin, r, "admin.login.success", "", map[string]any{
		"role": admin.Role,
	})

	writeJSON(w, http.StatusOK, adminLoginResp{
		Token:     tok,
		ExpiresAt: exp,
		Admin:     adminMeFrom(admin),
	})
}

// =============================================================================
// GET /admin/auth/me — current admin
// =============================================================================

type adminMe struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	MFARequired bool       `json:"mfaRequired"`
	MFAEnabled  bool       `json:"mfaEnabled"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	LastLoginIP string     `json:"lastLoginIp,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func adminMeFrom(a *store.AdminUser) adminMe {
	return adminMe{
		ID:          a.ID,
		Email:       a.Email,
		Role:        a.Role,
		MFARequired: a.MFARequired,
		MFAEnabled:  a.MFASecret != "",
		LastLoginAt: a.LastLoginAt,
		LastLoginIP: a.LastLoginIP,
		CreatedAt:   a.CreatedAt,
	}
}

func (s *Server) handleAdminAuthMe(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	admin, err := s.store.GetAdminUserByEmail(r.Context(), a.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, adminMeFrom(admin))
}

// =============================================================================
// POST /admin/auth/totp/setup — generate secret + provisioning URI
// POST /admin/auth/totp/verify — confirm setup with a code
// DELETE /admin/auth/totp — disable TOTP (super_admin only)
// =============================================================================

type adminTOTPSetupResp struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func (s *Server) handleAdminTOTPSetup(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	setup, err := auth.GenerateTOTP(a.Email)
	if err != nil {
		writeInternal(w)
		return
	}
	if err := s.store.SetAdminMFASecret(r.Context(), a.ID, setup.Secret, false); err != nil {
		writeInternal(w)
		return
	}
	s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
		"admin.totp.setup_initiated", a.ID, nil)
	writeJSON(w, http.StatusOK, adminTOTPSetupResp{
		Secret: setup.Secret,
		URI:    setup.URI,
	})
}

type adminTOTPVerifyReq struct {
	Code string `json:"code"`
}

func (s *Server) handleAdminTOTPVerify(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req adminTOTPVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	admin, err := s.store.GetAdminUserByEmail(r.Context(), a.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "admin not found")
		return
	}
	if locked, until, _ := s.store.IsAdminLocked(r.Context(), admin.ID); locked {
		w.Header().Set("Retry-After", retryAfter(until))
		writeError(w, http.StatusTooManyRequests, "admin account temporarily locked, please retry later")
		return
	}
	if admin.MFASecret == "" {
		writeError(w, http.StatusBadRequest, "run /totp/setup first")
		return
	}
	lastWindow, lwErr := s.store.GetAdminTOTPLastWindow(r.Context(), admin.ID)
	if lwErr != nil && !errors.Is(lwErr, store.ErrNotFound) {
		slog.Default().Warn("admin totp verify: last window lookup failed",
			"admin_id", admin.ID, "err", lwErr)
	}
	window, err := auth.VerifyTOTP(admin.MFASecret, req.Code, lastWindow)
	if err != nil {
		if incErr := s.store.IncrementAdminFailedLogin(r.Context(), admin.ID, AdminLockoutThreshold, AdminLockoutDuration); incErr != nil {
			slog.Default().Warn("admin totp verify: increment failed login failed",
				"admin_id", admin.ID, "err", incErr)
		}
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}
	if setErr := s.store.SetAdminTOTPLastWindow(r.Context(), admin.ID, window); setErr != nil {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}
	if err := s.store.ResetAdminFailedLogin(r.Context(), admin.ID); err != nil {
		slog.Default().Warn("admin totp verify: reset failed login failed",
			"admin_id", admin.ID, "err", err)
	}
	if err := s.store.SetAdminMFASecret(r.Context(), admin.ID, admin.MFASecret, true); err != nil {
		writeInternal(w)
		return
	}
	s.adminAuditAppend(r.Context(), admin, r, "admin.totp.enabled", admin.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil || a.Role != "super_admin" {
		writeError(w, http.StatusForbidden, "super_admin role required")
		return
	}
	if err := s.store.SetAdminMFASecret(r.Context(), a.ID, "", false); err != nil {
		writeInternal(w)
		return
	}
	s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
		"admin.totp.disabled", a.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// /admin/admin-users — manage admin accounts (super_admin only)
// =============================================================================

type adminCreateAdminUserReq struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	MFARequired bool   `json:"mfaRequired"`
}

func (s *Server) handleAdminCreateAdminUser(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil || a.Role != "super_admin" {
		writeError(w, http.StatusForbidden, "super_admin role required")
		return
	}
	var req adminCreateAdminUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	hashed, err := auth.HashAdminPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in := store.AdminUserCreate{
		Email:          strings.ToLower(strings.TrimSpace(req.Email)),
		HashedPassword: hashed,
		Role:           strings.ToLower(strings.TrimSpace(req.Role)),
		MFARequired:    req.MFARequired,
	}
	created, err := s.store.CreateAdminUser(r.Context(), in)
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "admin with this email already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.adminAuditAppend(r.Context(), &store.AdminUser{ID: a.ID, Email: a.Email}, r,
		"admin_user.created", created.ID, map[string]any{
			"email": created.Email,
			"role":  created.Role,
		})
	writeJSON(w, http.StatusCreated, adminMeFrom(created))
}

func (s *Server) handleAdminListAdminUsers(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	if a == nil || a.Role != "super_admin" {
		writeError(w, http.StatusForbidden, "super_admin role required")
		return
	}
	admins, err := s.store.ListAdminUsers(r.Context())
	if err != nil {
		writeInternal(w)
		return
	}
	out := make([]adminMe, 0, len(admins))
	for i := range admins {
		out = append(out, adminMeFrom(&admins[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": len(out)})
}

// =============================================================================
// /admin/audit — read the admin_audit_log
// =============================================================================

// handleAdminAuditList returns the most recent audit entries.
//
// Query params:
//   - `limit` (1..500, default 100). Caps how many rows the operator can pull
//     in one request — large dumps belong in offline tooling, not the
//     dashboard.
func (s *Server) handleAdminAuditList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			limit = n
		}
	}
	entries, err := s.store.ListAdminAudit(r.Context(), limit)
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "total": len(entries), "limit": limit})
}
