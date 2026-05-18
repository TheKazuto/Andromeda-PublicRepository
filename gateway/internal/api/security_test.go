package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCacheControl_NoStoreByDefault(t *testing.T) {
	h := cacheControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("expected no-store, got %q", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Authorization") {
		t.Errorf("expected Vary to include Authorization, got %q", rec.Header().Get("Vary"))
	}
}

func TestCacheControl_PublicAllowlist(t *testing.T) {
	for _, path := range []string{"/v1/capabilities", "/v1/info", "/openapi.json", "/health", "/v1/pricing/plans"} {
		t.Run(path, func(t *testing.T) {
			h := cacheControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(200)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
				t.Errorf("expected public/max-age=60, got %q", got)
			}
		})
	}
}

func TestCacheControl_RespectsHandlerOverride(t *testing.T) {
	h := cacheControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("handler value should win, got %q", got)
	}
}

func TestCacheControl_HandlesTrailingSlash(t *testing.T) {
	h := cacheControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/capabilities/", nil))
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("trailing slash should still hit allowlist, got %q", got)
	}
}

func TestSecurityHeaders_BaselineAlwaysPresent(t *testing.T) {
	h := securityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))

	cases := map[string]string{
		"X-Content-Type-Options":        "nosniff",
		"X-Frame-Options":               "DENY",
		"Referrer-Policy":               "strict-origin-when-cross-origin",
		"Cross-Origin-Resource-Policy":  "same-origin",
	}
	for k, want := range cases {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("header %s: got %q want %q", k, got, want)
		}
	}
	if !strings.Contains(rec.Header().Get("Permissions-Policy"), "interest-cohort=()") {
		t.Errorf("Permissions-Policy missing interest-cohort guard: %q", rec.Header().Get("Permissions-Policy"))
	}
}

func TestSecurityHeaders_HSTSOnlyInProdHTTPS(t *testing.T) {
	// dev: no HSTS regardless of scheme
	h := securityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("dev should not emit HSTS, got %q", got)
	}

	// prod + http: still no HSTS (we only send it over TLS)
	h = securityHeadersMiddleware(true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	// no XFP header → not HTTPS
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("prod+http should not emit HSTS, got %q", got)
	}

	// prod + https via XFP: HSTS present
	h = securityHeadersMiddleware(true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(rec, req)
	got := rec.Header().Get("Strict-Transport-Security")
	if !strings.Contains(got, "max-age=") || !strings.Contains(got, "preload") {
		t.Errorf("prod+https should emit HSTS with max-age + preload, got %q", got)
	}
}

func TestIsPublicCacheable(t *testing.T) {
	cases := map[string]bool{
		"/v1/capabilities":   true,
		"/v1/capabilities/":  true,
		"/v1/me":             false,
		"/admin/users":       false,
		"/v1/auth/login":     false,
		"/openapi.json":      true,
		"/v1/pricing/plans":  true,
	}
	for path, want := range cases {
		if got := isPublicCacheable(path); got != want {
			t.Errorf("isPublicCacheable(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestJoinVary_NoDuplicates(t *testing.T) {
	got := joinVary("Authorization", "Authorization", "X-Api-Key")
	if !strings.Contains(got, "Authorization") || !strings.Contains(got, "X-Api-Key") {
		t.Errorf("missing values: %q", got)
	}
	if strings.Count(got, "Authorization") != 1 {
		t.Errorf("duplicate Authorization: %q", got)
	}
}
