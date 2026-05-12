package api

import (
	"net/http"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// writeJSON / writeError are thin aliases over internal/httpx so the whole
// gateway emits one error envelope: {"error": "...", "code": "..."}.
func writeJSON(w http.ResponseWriter, code int, payload any) {
	httpx.WriteJSON(w, code, payload)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	httpx.WriteError(w, status, code, msg)
}
