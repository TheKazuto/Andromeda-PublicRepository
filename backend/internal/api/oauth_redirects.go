// Login Social — tenant OAuth redirect URI CRUD.
//
// Mounted at `/v1/oauth/redirects` behind `RequireAuth` (dashboard JWT).
// Each tenant manages ITS OWN allowlist; the gateway's broker
// (`/v1/oauth/authorize`) rejects any `redirect_uri` not in this list.
//
// Schema lives in the gateway migration `023_tenant_oauth_redirects.sql`
// (backend + gateway share the same Postgres).

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// Limits enforced on the input. They mirror what the gateway broker validates
// at /authorize time (`gateway/internal/oauth/handlers.go::isHTTPSOrLocal`),
// plus a per-tenant cap so a runaway client can't DoS the allowlist table.
const (
	maxRedirectURILen        = 1024
	maxRedirectsPerTenant    = 20
	maxRedirectDescriptionLen = 200
)

type addOAuthRedirectReq struct {
	RedirectURI string `json:"redirectUri"`
	Description string `json:"description"`
}

// GET /v1/oauth/redirects
func (s *Server) handleListOAuthRedirects(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	rows, err := s.store.ListTenantOAuthRedirects(r.Context(), uid)
	if err != nil {
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

// POST /v1/oauth/redirects
func (s *Server) handleAddOAuthRedirect(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	var req addOAuthRedirectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.RedirectURI = strings.TrimSpace(req.RedirectURI)
	req.Description = strings.TrimSpace(req.Description)

	if msg := validateRedirectURI(req.RedirectURI, s.cfg.Env == "production"); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if len(req.Description) > maxRedirectDescriptionLen {
		writeError(w, http.StatusBadRequest, "description must be <= 200 chars")
		return
	}

	// Per-tenant cap.
	existing, err := s.store.ListTenantOAuthRedirects(r.Context(), uid)
	if err != nil {
		writeInternal(w)
		return
	}
	if len(existing) >= maxRedirectsPerTenant {
		writeError(w, http.StatusBadRequest, "max 20 redirect URIs per tenant — delete unused entries first")
		return
	}

	row := &store.TenantOAuthRedirect{
		UserID:      uid,
		RedirectURI: req.RedirectURI,
		Description: req.Description,
	}
	if err := s.store.AddTenantOAuthRedirect(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "redirect URI already registered")
			return
		}
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusCreated, row)
}

// DELETE /v1/oauth/redirects?redirectUri=<uri>
//
// The URI is passed as a query param (not a path segment) because URLs
// contain `/` and `:` which would clash with chi's pattern matching.
func (s *Server) handleDeleteOAuthRedirect(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	uri := strings.TrimSpace(r.URL.Query().Get("redirectUri"))
	if uri == "" {
		writeError(w, http.StatusBadRequest, "missing redirectUri query parameter")
		return
	}
	if err := s.store.RemoveTenantOAuthRedirect(r.Context(), uid, uri); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "redirect URI not found")
			return
		}
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateRedirectURI mirrors the gateway's allowlist guard. Returns an empty
// string when valid, or a user-facing error message otherwise.
//
//   - https://… is always allowed
//   - http://localhost[:port]… is allowed in non-production
//   - everything else (ftp, javascript:, etc.) is rejected
//   - max length, no fragments, no query is enforced loosely (Google / Apple
//     don't tolerate URI variants well; keeping it strict here matches them).
func validateRedirectURI(uri string, isProd bool) string {
	if uri == "" {
		return "redirectUri is required"
	}
	if len(uri) > maxRedirectURILen {
		return "redirectUri must be <= 1024 chars"
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "redirectUri must be an absolute URL"
	}
	if u.Fragment != "" {
		return "redirectUri must not contain a fragment (#...)"
	}
	if u.Scheme == "https" {
		return ""
	}
	if u.Scheme == "http" && !isProd {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" {
			return ""
		}
	}
	return "redirectUri must be https:// (http://localhost allowed in development only)"
}

// chiURLParam wraps chi.URLParam so the import is still used. (Unused right
// now but kept for the eventual `:id`-based DELETE if we ever switch.)
var _ = chi.URLParam
