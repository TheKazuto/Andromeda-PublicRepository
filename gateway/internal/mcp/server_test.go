package mcp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// fakeCharger implements ToolCharger + Refundable and counts calls.
type fakeCharger struct {
	charges   int
	refunds   int
	chargeErr error // when set, Charge fails with this
}

func (c *fakeCharger) Charge(context.Context, *http.Request, string) (Refundable, error) {
	c.charges++
	if c.chargeErr != nil {
		return nil, c.chargeErr
	}
	return c, nil
}
func (c *fakeCharger) Refund(context.Context) { c.refunds++ }

// newMCPHandler wires a tool registry against an httptest engine.
func newMCPHandler(t *testing.T, engine http.Handler, charger ToolCharger) *Handler {
	t.Helper()
	ts := httptest.NewServer(engine)
	t.Cleanup(ts.Close)
	reg, err := upstream.NewRegistryWithObserver(&config.Config{
		IkaUpstreamURL:  ts.URL,
		InternalAPIKey:  "test-internal-key",
		UpstreamTimeout: 5 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("upstream registry: %v", err)
	}
	return NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), NewToolRegistry(reg), charger)
}

// callTool issues a tools/call JSON-RPC request and returns the parsed result map.
func callTool(t *testing.T, h http.Handler, tool string) (status int, result map[string]any, rpcErr *rpcError) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"body":{}}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rpc response %q: %v", rec.Body.String(), err)
	}
	if resp.Error != nil {
		return rec.Code, nil, resp.Error
	}
	m, _ := resp.Result.(map[string]any)
	return rec.Code, m, nil
}

func isErrResult(m map[string]any) bool {
	v, _ := m["isError"].(bool)
	return v
}

func engineReplying(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func TestMCPCharge_Success(t *testing.T) {
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(200, `{"ok":true}`), fc)
	_, res, rpcErr := callTool(t, h, "ika.dkg.prepare")
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	if isErrResult(res) {
		t.Fatalf("200 upstream should not be an error result: %+v", res)
	}
	if fc.charges != 1 || fc.refunds != 0 {
		t.Fatalf("charges=%d refunds=%d, want 1/0", fc.charges, fc.refunds)
	}
}

func TestMCPCharge_4xxNoRefund(t *testing.T) {
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(400, `{"error":"bad request"}`), fc)
	_, res, rpcErr := callTool(t, h, "ika.dkg.prepare")
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	if !isErrResult(res) {
		t.Fatal("4xx upstream must surface IsError")
	}
	if fc.charges != 1 || fc.refunds != 0 {
		t.Fatalf("charges=%d refunds=%d, want 1/0 (caller's fault stays charged)", fc.charges, fc.refunds)
	}
}

func TestMCPCharge_5xxRefunds(t *testing.T) {
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(503, `{"error":"engine down"}`), fc)
	_, res, rpcErr := callTool(t, h, "ika.dkg.prepare")
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	if !isErrResult(res) {
		t.Fatal("5xx upstream must surface IsError")
	}
	if fc.charges != 1 || fc.refunds != 1 {
		t.Fatalf("charges=%d refunds=%d, want 1/1 (5xx refunds)", fc.charges, fc.refunds)
	}
}

func TestMCPCharge_TransportErrorRefunds(t *testing.T) {
	fc := &fakeCharger{}
	// Build a registry whose ika upstream points at a server we immediately close.
	ts := httptest.NewServer(http.NotFoundHandler())
	addr := ts.URL
	ts.Close() // dial will now fail
	reg, err := upstream.NewRegistryWithObserver(&config.Config{
		IkaUpstreamURL:  addr,
		InternalAPIKey:  "k",
		UpstreamTimeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), NewToolRegistry(reg), fc)
	_, res, rpcErr := callTool(t, h, "ika.dkg.prepare")
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	if !isErrResult(res) {
		t.Fatal("transport failure must surface IsError")
	}
	if fc.charges != 1 || fc.refunds != 1 {
		t.Fatalf("charges=%d refunds=%d, want 1/1 (transport failure refunds)", fc.charges, fc.refunds)
	}
}

func TestMCPCharge_QuotaExceeded(t *testing.T) {
	fc := &fakeCharger{chargeErr: QuotaError("token quota exceeded")}
	h := newMCPHandler(t, engineReplying(200, `{"ok":true}`), fc)
	status, _, rpcErr := callTool(t, h, "ika.dkg.prepare")
	if rpcErr == nil {
		t.Fatal("quota exceeded should produce a JSON-RPC error")
	}
	if rpcErr.Code != -32000 {
		t.Fatalf("rpc error code = %d, want -32000", rpcErr.Code)
	}
	if status != http.StatusPaymentRequired {
		t.Fatalf("http status = %d, want 402", status)
	}
	if fc.charges != 1 || fc.refunds != 0 {
		t.Fatalf("charges=%d refunds=%d, want 1/0 (charge failed → nothing to refund)", fc.charges, fc.refunds)
	}
}

func TestMCPCharge_UnknownTool(t *testing.T) {
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(200, `{}`), fc)
	status, _, rpcErr := callTool(t, h, "ika.does.not.exist")
	if rpcErr == nil || status != http.StatusNotFound {
		t.Fatalf("unknown tool: status=%d err=%+v, want 404 + rpc error", status, rpcErr)
	}
	if fc.charges != 0 {
		t.Fatalf("unknown tool must not charge, charges=%d", fc.charges)
	}
}

func TestMCPHandler_Initialize(t *testing.T) {
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(200, `{}`), fc)
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("initialize status=%d", rec.Code)
	}
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	m, _ := resp.Result.(map[string]any)
	if m["protocolVersion"] != ProtocolVersion {
		t.Fatalf("protocolVersion = %v, want %s", m["protocolVersion"], ProtocolVersion)
	}
}

func TestMCPHandler_GetOpensSSE(t *testing.T) {
	// GET /mcp must return text/event-stream with the initial frame — and
	// crucially must NOT 500 (regression guard for the response-writer wrapper).
	fc := &fakeCharger{}
	h := newMCPHandler(t, engineReplying(200, `{}`), fc)
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /mcp status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "andromeda mcp stream ready") {
		t.Fatalf("first SSE frame = %q, want the ready comment", string(buf[:n]))
	}
}
