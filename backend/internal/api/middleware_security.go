package api

import (
	"net/http"
)

// securityHeaders applies a baseline of security response headers to every
// request. HSTS is only emitted in production to avoid pinning local dev
// loops to https.
func securityHeaders(prod bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-site")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
			if prod {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// maxBodyBytes caps the size of incoming request bodies. JSON bodies above
// this size return 413 (the underlying ServeHTTP will surface a generic
// "http: request body too large" but the json decoder catches it first and
// returns 400). Stripe webhook applies its own larger cap so this bound
// stays safe for the rest of the API.
const defaultMaxBodyBytes = 1 << 20 // 1 MiB

func maxBodyMiddleware(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
