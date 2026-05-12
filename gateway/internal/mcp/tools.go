package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// ToolHandler runs a single tool invocation. Implementations translate the
// tool arguments into upstream API calls (ika-backend or encrypt-backend).
type ToolHandler func(ctx context.Context, args map[string]any) (toolCallResult, error)

// ToolRegistry holds the tools advertised over MCP.
type ToolRegistry struct {
	mu       sync.RWMutex
	tools    map[string]Tool
	handlers map[string]ToolHandler
}

// NewToolRegistry builds a tool catalogue. When upstreams is non-nil, every
// catalogued route in routes.All becomes a callable tool that proxies to
// the corresponding engine. When upstreams is nil, tools are registered
// with a stub handler that reports "not configured" — useful for tests
// and bare-metal MCP catalogues.
func NewToolRegistry(upstreams *upstream.Registry) *ToolRegistry {
	r := &ToolRegistry{
		tools:    map[string]Tool{},
		handlers: map[string]ToolHandler{},
	}
	r.seedFromRoutes(upstreams, routes.All)
	r.seedDiscoveryTools(routes.All)
	return r
}

// Register adds (or replaces) a tool.
func (r *ToolRegistry) Register(t Tool, h ToolHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
	r.handlers[t.Name] = h
}

func (r *ToolRegistry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

func (r *ToolRegistry) Handler(name string) (ToolHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[name]
	return h, ok
}

// Count returns the number of registered tools.
func (r *ToolRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// pathParamRE matches chi-style path parameters: {id}, {dwalletAddress}, ...
var pathParamRE = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// seedFromRoutes turns each catalogued route into a tool. Tool name is
// the route Key (e.g. "ika.sign.submit"). Argument schema declares
// pathParams (when the path has placeholders), query (always optional)
// and body (for write methods).
func (r *ToolRegistry) seedFromRoutes(upstreams *upstream.Registry, all []routes.Route) {
	for _, route := range all {
		route := route // capture
		tool := buildToolFromRoute(route)
		var handler ToolHandler
		if upstreams == nil {
			handler = stubHandler(route.Key, "upstreams not configured")
		} else {
			handler = makeProxyHandler(upstreams, route)
		}
		r.Register(tool, handler)
	}
}

// seedDiscoveryTools adds gateway-introspection tools that don't proxy to
// an engine. Today: gateway.routes.list — returns the entire route catalogue
// so MCP clients can render a directory without an out-of-band schema fetch.
func (r *ToolRegistry) seedDiscoveryTools(all []routes.Route) {
	r.Register(
		Tool{
			Name:        "gateway.routes.list",
			Description: "List every REST route the gateway proxies. Each entry includes method, path, upstream engine and the canonical route key (which doubles as the MCP tool name).",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		func(_ context.Context, _ map[string]any) (toolCallResult, error) {
			items := make([]map[string]any, 0, len(all))
			for _, rt := range all {
				items = append(items, map[string]any{
					"key":          rt.Key,
					"method":       rt.Method,
					"path":         rt.Path,
					"upstream":     rt.Upstream,
					"idempotent":   rt.Idempotent,
					"upstreamPath": rt.TargetPath(),
				})
			}
			payload := map[string]any{
				"count":  len(items),
				"routes": items,
			}
			return toolCallResultFromJSON(payload), nil
		},
	)
}

func buildToolFromRoute(route routes.Route) Tool {
	hint, hasHint := routeHints[route.Key]
	params := pathParamNames(route.Path)
	props := map[string]any{}
	required := []string{}

	if len(params) > 0 {
		paramProps := map[string]any{}
		paramRequired := make([]string, 0, len(params))
		for _, p := range params {
			paramProps[p] = map[string]any{
				"type":        "string",
				"description": "Path parameter " + p,
			}
			paramRequired = append(paramRequired, p)
		}
		props["pathParams"] = map[string]any{
			"type":                 "object",
			"description":          "URL path parameters",
			"properties":           paramProps,
			"required":             paramRequired,
			"additionalProperties": false,
		}
		required = append(required, "pathParams")
	}

	props["query"] = map[string]any{
		"type":                 "object",
		"description":          "Optional query string parameters (string values).",
		"additionalProperties": map[string]any{"type": "string"},
	}

	if methodAcceptsBody(route.Method) {
		if hasHint && hint.BodySchema != nil {
			props["body"] = hint.BodySchema
			if hint.BodyRequired {
				required = append(required, "body")
			}
		} else {
			props["body"] = map[string]any{
				"type":                 "object",
				"description":          "JSON body forwarded verbatim to the engine. Shape matches the upstream contract for " + route.Path + ".",
				"additionalProperties": true,
			}
		}
	}

	schema := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}

	annotations := &ToolAnnotations{
		ReadOnlyHint:    route.RateClass == "read",
		DestructiveHint: route.RateClass != "read",
		IdempotentHint:  route.Idempotent,
		OpenWorldHint:   true, // every tool talks to ika or encrypt over the network
	}

	description := fmt.Sprintf("%s %s → %s-backend (custody-free proxy).", route.Method, route.Path, route.Upstream)
	if hasHint && hint.Description != "" {
		description = hint.Description
	}

	return Tool{
		Name:        route.Key,
		Description: description,
		InputSchema: schema,
		Annotations: annotations,
	}
}

func makeProxyHandler(upstreams *upstream.Registry, route routes.Route) ToolHandler {
	return func(ctx context.Context, args map[string]any) (toolCallResult, error) {
		target := upstreams.Get(route.Upstream)
		if target == nil {
			return toolCallTechnicalError("upstream " + route.Upstream + " not registered"), nil
		}

		path := route.TargetPath()
		if pp, ok := args["pathParams"].(map[string]any); ok {
			var err error
			path, err = substitutePathParams(path, pp)
			if err != nil {
				return toolCallError("invalid pathParams: " + err.Error()), nil
			}
		} else if pathParamRE.MatchString(path) {
			return toolCallError("missing pathParams for " + route.Path), nil
		}

		var query url.Values
		if q, ok := args["query"].(map[string]any); ok && len(q) > 0 {
			query = url.Values{}
			for k, v := range q {
				query.Set(k, fmt.Sprint(v))
			}
		}

		var bodyBytes []byte
		if methodAcceptsBody(route.Method) {
			if b, ok := args["body"]; ok && b != nil {
				marshaled, err := json.Marshal(b)
				if err != nil {
					return toolCallError("invalid body: " + err.Error()), nil
				}
				bodyBytes = marshaled
			} else {
				// Many engines accept POST with empty JSON body. Send {}.
				bodyBytes = []byte("{}")
			}
		}

		var extraHeaders map[string]string
		if tenant := TenantIdentityFrom(ctx); tenant != "" {
			// Mirror the REST proxy: tenant-scoped engine routes (e.g.
			// POST /v1/dwallet/create) reject calls without this header.
			extraHeaders = map[string]string{"X-Andromeda-User-Id": tenant}
		}

		res, err := target.Call(ctx, route.Method, path, query, bodyBytes, extraHeaders)
		if err != nil {
			// Transport / dial failure — the engine never serviced this. Refund.
			return toolCallTechnicalError("upstream call failed: " + err.Error()), nil
		}

		return toolCallResult{
			Content: []contentBlock{{Type: "text", Text: formatUpstreamReply(res)}},
			// A 4xx is the caller's fault → IsError, stays charged.
			// A 5xx means the engine could not service it → IsError + refund.
			IsError:         res.StatusCode >= 400,
			RefundableError: res.StatusCode >= 500,
		}, nil
	}
}

func methodAcceptsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func pathParamNames(path string) []string {
	matches := pathParamRE.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

func substitutePathParams(path string, params map[string]any) (string, error) {
	missing := []string{}
	out := pathParamRE.ReplaceAllStringFunc(path, func(token string) string {
		name := token[1 : len(token)-1] // strip { }
		v, ok := params[name]
		if !ok {
			missing = append(missing, name)
			return token
		}
		s := fmt.Sprint(v)
		return url.PathEscape(s)
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("missing path params: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func formatUpstreamReply(res *upstream.CallResult) string {
	if res == nil {
		return "<empty upstream response>"
	}
	body := strings.TrimSpace(string(res.Body))
	if body == "" {
		return fmt.Sprintf("HTTP %d (no body)", res.StatusCode)
	}
	return fmt.Sprintf("HTTP %d\n%s", res.StatusCode, body)
}

// toolCallError reports a caller-side error (bad arguments, missing path
// params, ...). It stays charged — RefundableError is left false.
func toolCallError(msg string) toolCallResult {
	return toolCallResult{
		Content: []contentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

// toolCallTechnicalError reports a gateway/upstream-side failure that the
// caller is not responsible for (upstream not configured, transport error).
// The per-tool quota charge is refunded.
func toolCallTechnicalError(msg string) toolCallResult {
	return toolCallResult{
		Content:         []contentBlock{{Type: "text", Text: msg}},
		IsError:         true,
		RefundableError: true,
	}
}

func toolCallResultFromJSON(payload any) toolCallResult {
	enc, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return toolCallError("marshal payload: " + err.Error())
	}
	return toolCallResult{
		Content: []contentBlock{{Type: "text", Text: string(enc)}},
	}
}

func stubHandler(name, reason string) ToolHandler {
	return func(_ context.Context, _ map[string]any) (toolCallResult, error) {
		return toolCallError(fmt.Sprintf("tool %q unavailable: %s", name, reason)), nil
	}
}
