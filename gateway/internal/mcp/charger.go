package mcp

import (
	"context"
	"net/http"
)

// ToolCharger is the dependency the MCP handler uses to deduct quota
// per tool call. Defined as an interface here so the mcp package
// stays free of imports on api / pricing / store — concrete impl
// lives in the api package.
//
// Charge is invoked BEFORE the tool runs. On success it returns a
// Refundable that the handler will Refund() if the tool reports
// IsError or returns an error.
type ToolCharger interface {
	Charge(ctx context.Context, r *http.Request, toolKey string) (Refundable, error)
}

// Refundable wraps the side effect of "undo my charge" — the api
// package implements this with the same RefundTokensV2 path used by
// the REST proxy on 5xx upstream.
type Refundable interface {
	Refund(ctx context.Context)
}

// chargerError is returned by Charge when the user is out of quota.
// Carries the JSON-RPC code so the handler can pick the right reply.
type chargerError struct {
	msg  string
	code int
}

func (e *chargerError) Error() string { return e.msg }

// QuotaError builds a charger error that maps to JSON-RPC -32000 with
// a custom message — the handler uses it to surface a 402-equivalent.
func QuotaError(msg string) error { return &chargerError{msg: msg, code: -32000} }
