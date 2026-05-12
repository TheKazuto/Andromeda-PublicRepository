// Package httpx holds the gateway's shared HTTP response helpers so every
// REST surface emits the same shapes. The error envelope is:
//
//	{"error": "<human message>", "code": "<snake_case_code>"}
//
// — flat, two string fields. (The MCP endpoint is exempt: JSON-RPC has its
// own error object and is not part of the REST contract.)
package httpx

import (
	"encoding/json"
	"net/http"
)

// errorBody is the canonical error envelope. `code` is optional but
// callers should always supply one.
type errorBody struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// WriteJSON writes payload as JSON with the given status. Used for both
// success and error responses (pass an errorBody for the latter, or use
// WriteError).
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteError writes the canonical {error, code} envelope.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, errorBody{Error: msg, Code: code})
}
