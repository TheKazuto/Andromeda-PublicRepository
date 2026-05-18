package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"
)

// MaxRequestBytes caps incoming request bodies. 10 MiB covers the
// largest engine payload we actually see in production (FHE graphs)
// while keeping a malicious client from pinning hundreds of MB of
// memory per request. Operators can override via GATEWAY_MAX_BODY_BYTES
// when an experimental payload exceeds the default.
//
// Mutating, signing-sensitive routes carry per-route caps (1 MiB) set
// at the handler level — this constant is the broad safety net.
var MaxRequestBytes int64 = func() int64 {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_MAX_BODY_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 10 << 20
}()

// limitPayload caps the request body at `max` bytes. Excess streams fail with
// 413 Payload Too Large the moment the handler reads past the limit. GET / HEAD
// are passed through untouched.
func limitPayload(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}
