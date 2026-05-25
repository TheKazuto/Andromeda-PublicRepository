package httpx

import (
	"crypto/subtle"
	"net/http"
)

// RequireInternalKey gates every non-health route behind the shared
// X-Internal-Key secret. The intents-backend lives in the Railway private
// network and is only ever called by the gateway; this is defense-in-depth so
// a misrouted public request can never reach it.
//
// When expected is empty (development with the env unset) the guard is a
// pass-through — the config layer already forces a value in production.
func RequireInternalKey(expected string) func(http.Handler) http.Handler {
	expectedBytes := []byte(expected)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expected == "" {
				next.ServeHTTP(w, r)
				return
			}
			got := r.Header.Get("X-Internal-Key")
			if subtle.ConstantTimeCompare([]byte(got), expectedBytes) != 1 {
				WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid internal key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
