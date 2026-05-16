package mcp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestLoopbackHandlerWithoutMux exercises the fallback path: a Local
// tool invoked before the API layer has injected an http.Handler must
// return a clear error (not panic) and stay refundable so the caller
// isn't charged for a misconfigured gateway.
func TestLoopbackHandlerWithoutMux(t *testing.T) {
	reg := NewToolRegistry(nil)
	h, ok := reg.Handler("policy.engine.init.challenge")
	if !ok {
		t.Fatal("policy.engine.init.challenge tool not registered")
	}
	ctx := WithLoopbackInbound(context.Background(), &LoopbackInbound{
		Headers: http.Header{"X-Api-Key": {"sk_test"}},
	})
	res, err := h(ctx, map[string]any{"body": map[string]any{}})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError when loopback handler is not wired")
	}
	if !res.RefundableError {
		t.Fatal("missing loopback config is a gateway-side fault — must refund")
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "loopback handler not configured") {
		t.Errorf("expected fallback message, got: %#v", res.Content)
	}
}

// TestLoopbackHandlerMissingInbound covers the defensive branch: even
// when the mux is wired, calling a Local tool without going through the
// MCP server (which stashes the inbound headers) must surface a clear
// technical error.
func TestLoopbackHandlerMissingInbound(t *testing.T) {
	reg := NewToolRegistry(nil)
	reg.SetLoopbackHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h, _ := reg.Handler("policy.engine.init.challenge")
	res, err := h(context.Background(), map[string]any{"body": map[string]any{}})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !res.IsError || !res.RefundableError {
		t.Fatal("missing inbound context is a gateway-side fault")
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "inbound request context not set") {
		t.Errorf("unexpected message: %#v", res.Content)
	}
}

// TestLoopbackHandlerSuccess wires a fake mux that records what the
// loopback synthesised, then asserts the tool round-trips: method,
// path, JSON body, forwarded headers, the loopback context marker,
// and the response back to the MCP caller.
func TestLoopbackHandlerSuccess(t *testing.T) {
	type capture struct {
		method    string
		path      string
		body      string
		apiKey    string
		isLoopbck bool
		contentT  string
	}
	cap := &capture{}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.apiKey = r.Header.Get("X-Api-Key")
		cap.contentT = r.Header.Get("Content-Type")
		cap.isLoopbck = IsLoopback(r.Context())
		b, _ := io.ReadAll(r.Body)
		cap.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"engine_address":"PE111"}`))
	})

	reg := NewToolRegistry(nil)
	reg.SetLoopbackHandler(mux)
	h, _ := reg.Handler("policy.engine.init.challenge")

	ctx := WithLoopbackInbound(context.Background(), &LoopbackInbound{
		Headers: http.Header{
			"X-Api-Key":    {"sk_live_test"},
			"User-Agent":   {"mcp-client/1.0"},
			"X-Should-Not": {"forwarded"},
		},
		RemoteAddr: "10.0.0.1:54321",
	})
	res, err := h(ctx, map[string]any{
		"body": map[string]any{
			"dwallet_address":     "5nFrBSDXkME6qt2yXh2Y5N1je3ptQnYgXg9BtpTiyqqX",
			"init_authority_slot": "AA==",
			"owner_slot":          "AA==",
		},
	})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %#v", res.Content)
	}
	if cap.method != "POST" {
		t.Errorf("method = %q, want POST", cap.method)
	}
	if cap.path != "/v1/policy/init/challenge" {
		t.Errorf("path = %q, want /v1/policy/init/challenge", cap.path)
	}
	if cap.apiKey != "sk_live_test" {
		t.Errorf("X-Api-Key header not forwarded: %q", cap.apiKey)
	}
	if cap.contentT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", cap.contentT)
	}
	if !cap.isLoopbck {
		t.Error("IsLoopback(ctx) should be true inside the synthesised request")
	}
	if !strings.Contains(cap.body, "dwallet_address") {
		t.Errorf("body not marshalled correctly: %q", cap.body)
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "engine_address") {
		t.Errorf("response body not echoed back: %#v", res.Content)
	}
	if !strings.Contains(res.Content[0].Text, "HTTP 200") {
		t.Errorf("expected HTTP 200 prefix in response: %q", res.Content[0].Text)
	}
}

// TestLoopbackHandlerPathParams confirms path-template substitution
// runs against args["pathParams"] and that missing params produce a
// caller-side error (IsError + not refundable).
func TestLoopbackHandlerPathParams(t *testing.T) {
	var seenPath string
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	reg := NewToolRegistry(nil)
	reg.SetLoopbackHandler(mux)
	h, _ := reg.Handler("policy.engine.read")

	ctx := WithLoopbackInbound(context.Background(), &LoopbackInbound{
		Headers: http.Header{"X-Api-Key": {"sk_x"}},
	})

	res, err := h(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !res.IsError {
		t.Fatal("missing pathParam must be a caller-side error")
	}
	if res.RefundableError {
		t.Error("a missing-path-param error is caller's fault — must not refund")
	}

	res, err = h(ctx, map[string]any{
		"pathParams": map[string]any{"dwallet": "ABC"},
	})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if res.IsError {
		t.Fatalf("happy path returned IsError: %#v", res.Content)
	}
	if seenPath != "/v1/policy/ABC" {
		t.Errorf("path substitution wrong: %q", seenPath)
	}
}
