package mcp

import (
	"context"
	"net/http"
)

type ctxKey int

const (
	ctxKeyTenantID ctxKey = iota
	ctxKeyLoopback
	ctxKeyLoopbackInbound
)

// WithTenantIdentity stashes the calling tenant's identity on the context.
// The HTTP layer that mounts the MCP handler sets it right after it has
// authenticated the API key; the proxy tool handlers read it back and
// forward it to the upstream engines as the `X-Andromeda-User-Id` header
// (the same header the REST proxy sends), so tenant-scoped routes such as
// `POST /v1/dwallet/create` know who is calling.
//
// Without this the ika-backend rejects the request with
// 401 "missing tenant identity — call this endpoint through the Andromeda
// gateway", because the gateway *was* the caller but never identified the
// tenant.
func WithTenantIdentity(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyTenantID, id)
}

// TenantIdentityFrom returns the tenant identity set by WithTenantIdentity,
// or "" when absent.
func TenantIdentityFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyTenantID).(string)
	return v
}

// WithLoopback marks the request as an in-process MCP loopback call (a
// Local route reached through the MCP tool registry rather than over the
// public mux). The REST middleware uses this flag to skip per-call
// billing — the MCP tool charger has already debited the per-tool token
// cost, so charging again in chargeQuota would double-charge.
//
// The flag is set ONLY by makeLoopbackHandler; the context value isn't
// serializable, so it cannot be spoofed by an external caller.
func WithLoopback(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyLoopback, true)
}

// IsLoopback reports whether the context was marked by WithLoopback.
func IsLoopback(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyLoopback).(bool)
	return v
}

// LoopbackInbound carries the inbound MCP request's headers + remote
// address so a Local tool handler can rebuild an internal *http.Request
// with the same auth/quota context (X-Api-Key, Authorization, Origin, …)
// before serving it on the gateway's own mux.
type LoopbackInbound struct {
	Headers    http.Header
	RemoteAddr string
}

// WithLoopbackInbound stashes the inbound MCP request's identifying bits
// on the context. The MCP handler sets this just before invoking the tool
// handler so loopback tools can mint a faithful sibling request.
func WithLoopbackInbound(ctx context.Context, lb *LoopbackInbound) context.Context {
	if lb == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyLoopbackInbound, lb)
}

// LoopbackInboundFrom returns the LoopbackInbound bundle set by
// WithLoopbackInbound, or nil when absent.
func LoopbackInboundFrom(ctx context.Context) *LoopbackInbound {
	v, _ := ctx.Value(ctxKeyLoopbackInbound).(*LoopbackInbound)
	return v
}
