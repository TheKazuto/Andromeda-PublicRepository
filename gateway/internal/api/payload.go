package api

import "net/http"

// MaxRequestBytes caps incoming request bodies. 25 MiB is generous enough for
// the largest engine payload we expect (encrypted graphs) while bounding the
// memory cost of a malicious client. Applied via the limitPayload middleware.
const MaxRequestBytes int64 = 25 << 20

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
