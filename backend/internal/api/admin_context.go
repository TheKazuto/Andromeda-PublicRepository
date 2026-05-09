package api

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type adminCtxKey int

const ctxKeyAdmin adminCtxKey = iota

// adminIdentity is the minimal slice of admin info that handlers need:
// who is making the call (id, email, role). Kept in context so audit
// logging and role checks don't have to re-parse the JWT.
type adminIdentity struct {
	ID    string
	Email string
	Role  string
}

func withAdmin(r *http.Request, a *adminIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyAdmin, a))
}

func adminFrom(r *http.Request) *adminIdentity {
	v, _ := r.Context().Value(ctxKeyAdmin).(*adminIdentity)
	return v
}

// bearerToken extracts a Bearer token from the Authorization header.
// Returns "" if absent or malformed.
func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(v) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(v[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(v[len(prefix):])
}

// clientIP picks the direct peer IP for audit and auth rate limiting.
// Proxy-forwarded headers are intentionally ignored unless a trusted proxy
// layer normalizes RemoteAddr before the request reaches this process.
func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.Trim(r.RemoteAddr, "[]")
}
