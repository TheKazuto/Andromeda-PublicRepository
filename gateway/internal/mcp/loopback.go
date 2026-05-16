package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

// loopbackForwardedHeaders is the allow-list of inbound headers copied
// onto the synthetic loopback request. Anything not in this list is
// dropped — we don't want stray headers (Cookie, Content-Length from the
// JSON-RPC envelope, …) leaking into the in-process call.
//
// X-Andromeda-* are gateway-internal trust signals already vetted on the
// MCP-side; passing them straight through keeps the policy middleware
// (e.g. tenant-id forwarding) behaving identically to direct REST hits.
var loopbackForwardedHeaders = []string{
	"X-Api-Key",
	"Authorization",
	"Origin",
	"X-Forwarded-For",
	"X-Real-Ip",
	"Idempotency-Key",
	"X-Andromeda-User-Id",
	"User-Agent",
}

// makeLoopbackHandler returns a ToolHandler for a Local route. The handler
// converts the MCP tool arguments (pathParams + query + body) into a
// regular *http.Request, copies the inbound request's auth headers, marks
// the context as a loopback call (so chargeQuota knows to skip the
// per-call billing — the MCP tool charger already debited the token cost),
// and serves it on the gateway's own mux.
//
// When the registry's loopback handler hasn't been injected yet (the API
// layer wires it after the chi router is built), the call returns a
// helpful error pointing the caller at the REST endpoint instead.
func makeLoopbackHandler(reg *ToolRegistry, route routes.Route) ToolHandler {
	return func(ctx context.Context, args map[string]any) (toolCallResult, error) {
		mux := reg.loopbackHandler()
		if mux == nil {
			return toolCallTechnicalError(
				"loopback handler not configured — call " +
					route.Method + " " + route.Path +
					" directly via REST (same auth/idempotency middleware applies)",
			), nil
		}

		inbound := LoopbackInboundFrom(ctx)
		if inbound == nil {
			return toolCallTechnicalError("loopback: inbound request context not set"), nil
		}

		target := route.Path
		if pp, ok := args["pathParams"].(map[string]any); ok {
			var err error
			target, err = substitutePathParams(target, pp)
			if err != nil {
				return toolCallError("invalid pathParams: " + err.Error()), nil
			}
		} else if pathParamRE.MatchString(target) {
			return toolCallError("missing pathParams for " + route.Path), nil
		}

		if q, ok := args["query"].(map[string]any); ok && len(q) > 0 {
			qs := url.Values{}
			for k, v := range q {
				qs.Set(k, fmt.Sprint(v))
			}
			target = target + "?" + qs.Encode()
		}

		var bodyReader io.Reader
		var hasBody bool
		if methodAcceptsBody(route.Method) {
			var raw []byte
			if b, ok := args["body"]; ok && b != nil {
				m, err := json.Marshal(b)
				if err != nil {
					return toolCallError("invalid body: " + err.Error()), nil
				}
				raw = m
			} else {
				raw = []byte("{}")
			}
			bodyReader = bytes.NewReader(raw)
			hasBody = true
		}

		req, err := http.NewRequestWithContext(WithLoopback(ctx), route.Method, target, bodyReader)
		if err != nil {
			return toolCallTechnicalError("build loopback request: " + err.Error()), nil
		}

		for _, name := range loopbackForwardedHeaders {
			if v := inbound.Headers.Get(name); v != "" {
				req.Header.Set(name, v)
			}
		}
		if hasBody && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if inbound.RemoteAddr != "" {
			req.RemoteAddr = inbound.RemoteAddr
		}

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		body, _ := io.ReadAll(rec.Body)
		text := fmt.Sprintf("HTTP %d\n%s", rec.Code, strings.TrimSpace(string(body)))
		return toolCallResult{
			Content: []contentBlock{{Type: "text", Text: text}},
			// A 4xx is the caller's fault (bad args, missing scope) → IsError,
			// stays charged. A 5xx means the gateway/local service couldn't
			// service it → IsError + refundable.
			IsError:         rec.Code >= 400,
			RefundableError: rec.Code >= 500,
		}, nil
	}
}
