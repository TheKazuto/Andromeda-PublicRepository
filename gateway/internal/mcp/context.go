package mcp

import "context"

type ctxKey int

const ctxKeyTenantID ctxKey = iota

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
