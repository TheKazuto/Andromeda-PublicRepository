// Package httpx holds the shared HTTP plumbing for the intents-backend:
// a consistent JSON envelope, panic recovery, internal-key auth and the
// chi server wiring. Mirrors the gateway's conventions so error shapes are
// uniform across the platform.
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON serializes v as JSON with the given status. Encoding errors are
// swallowed after the header is written (nothing useful can be done then).
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the canonical {error, code} envelope. The message must be
// sanitized by the caller — never pass a raw upstream error or stack trace.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]string{"error": message, "code": code})
}

// DecodeJSON reads and strictly decodes the request body into v. Unknown
// fields are rejected so a typo in a caller payload fails loudly instead of
// being silently dropped.
func DecodeJSON(r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
