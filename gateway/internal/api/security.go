package api

import (
	"net/http"
	"strings"
)

// publicCacheablePaths is the explicit allowlist of routes that may be
// cached at the CDN. Everything else gets Cache-Control: no-store so
// tenant-specific responses (auth, signing, recovery, billing, usage,
// admin, MCP) never leak across users via Cloudflare or an
// intermediate proxy.
//
// Public surfaces (no API key required, identical bytes for everyone).
// Paths mirror gateway/internal/api/server.go exactly — handlers that
// set their own Cache-Control (e.g. /openapi.json sets max-age=300) win
// over this fallback, so the allowlist only kicks in when the handler
// stayed silent.
var publicCacheablePaths = map[string]bool{
	"/capabilities":     true,
	"/openapi.json":     true,
	"/openapi.yaml":     true,
	"/v1/pricing":       true,
	"/health":           true,
	"/health/ready":     true,
}

// cacheControlMiddleware applies a safe default of `no-store` to every
// response unless the handler explicitly set a different Cache-Control
// header. Public allowlisted routes get `public, max-age=60` so the
// CDN can absorb burst traffic; everything else is private.
//
// Handlers that need to override (e.g. an OpenAPI build with a long
// max-age) MUST set Cache-Control before calling w.Write — the
// middleware respects any value the handler set.
func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the writer so we can inject Cache-Control at WriteHeader
		// time (after the handler has had a chance to set its own).
		ww := &cacheControlWriter{ResponseWriter: w, path: r.URL.Path}
		next.ServeHTTP(ww, r)
	})
}

type cacheControlWriter struct {
	http.ResponseWriter
	path        string
	wroteHeader bool
}

func (c *cacheControlWriter) WriteHeader(status int) {
	if !c.wroteHeader {
		c.wroteHeader = true
		if c.ResponseWriter.Header().Get("Cache-Control") == "" {
			if isPublicCacheable(c.path) {
				c.ResponseWriter.Header().Set("Cache-Control", "public, max-age=60")
			} else {
				c.ResponseWriter.Header().Set("Cache-Control", "no-store")
			}
		}
		c.ResponseWriter.Header().Set("Vary", joinVary(c.ResponseWriter.Header().Get("Vary"), "Authorization", "X-Api-Key"))
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *cacheControlWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(p)
}

func isPublicCacheable(path string) bool {
	if publicCacheablePaths[path] {
		return true
	}
	// Trim trailing slash to match /v1/capabilities/ etc.
	trimmed := strings.TrimRight(path, "/")
	if trimmed != path && publicCacheablePaths[trimmed] {
		return true
	}
	return false
}

// joinVary appends `add` headers to an existing Vary value without
// duplicates. Vary is comma-separated, case-insensitive.
func joinVary(existing string, add ...string) string {
	seen := map[string]bool{}
	parts := []string{}
	for _, e := range strings.Split(existing, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		key := strings.ToLower(e)
		if !seen[key] {
			seen[key] = true
			parts = append(parts, e)
		}
	}
	for _, a := range add {
		a = strings.TrimSpace(a)
		key := strings.ToLower(a)
		if !seen[key] {
			seen[key] = true
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, ", ")
}

// securityHeadersMiddleware applies a baseline of defence-in-depth
// HTTP headers to every response. HSTS is only set when serving over
// HTTPS in production — emitting it in dev (http://localhost) confuses
// browsers when developers later test against the prod URL.
//
// CSP is deliberately *not* applied to API responses (JSON has no
// scripts to constrain). The dashboard sets its own CSP via
// Cloudflare Pages `_headers` (see `dashboard/public/_headers`).
func securityHeadersMiddleware(production bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// MIME-sniffing prevention. Default for any JSON API.
			h.Set("X-Content-Type-Options", "nosniff")
			// Refuse to be framed — the API is not designed for embeds,
			// and clickjacking on /admin would be especially nasty.
			h.Set("X-Frame-Options", "DENY")
			// Be conservative about Referer leakage. `strict-origin-when-
			// cross-origin` is the modern safe default.
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Permissions-Policy: no Privileged surfaces — no camera, mic,
			// geolocation, payment etc. — the API never needs them. This
			// affects iframed contexts only but is cheap to set.
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
			// Cross-Origin-Resource-Policy: same-origin keeps the JSON
			// payload from being read across origins via <link as=fetch>
			// preload tricks. Doesn't break the dashboard because the
			// dashboard fetches with credentials and CORS handles that.
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			// HSTS only when we know we're behind TLS termination —
			// Cloudflare/Railway add X-Forwarded-Proto for us.
			if production && isHTTPS(r) {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}
