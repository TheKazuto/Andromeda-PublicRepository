package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/pricing"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
	"github.com/shinkalabs/andromeda-gateway/internal/usage"
)

// fakeStore embeds store.Store so any method the proxy hot path doesn't use
// panics loudly if accidentally called. Only the lookup + quota methods are
// implemented.
type fakeStore struct {
	store.Store

	bundle    *store.AuthenticatedKey
	authErr   error
	consumeFn func(subID string, cost int) (*store.ConsumptionResult, error)
	consumed  int32
	refunded  int32
	touched   int32
}

func (f *fakeStore) AuthenticateAPIKey(context.Context, string) (*store.AuthenticatedKey, error) {
	return f.bundle, f.authErr
}
func (f *fakeStore) TouchAPIKeyUsed(context.Context, string) error {
	atomic.AddInt32(&f.touched, 1)
	return nil
}
func (f *fakeStore) ConsumeTokensV2(_ context.Context, subID string, cost int) (*store.ConsumptionResult, error) {
	atomic.AddInt32(&f.consumed, 1)
	if f.consumeFn != nil {
		return f.consumeFn(subID, cost)
	}
	sub := f.bundle.Subscription
	return &store.ConsumptionResult{
		Cost: cost, FromMonthly: cost, TokensUsed: int64(cost),
		Subscription: sub,
	}, nil
}
func (f *fakeStore) RefundTokensV2(context.Context, string, store.ConsumptionResult) error {
	atomic.AddInt32(&f.refunded, 1)
	return nil
}
func (f *fakeStore) ListRequestCosts(context.Context) ([]store.RequestCost, error) { return nil, nil }
func (f *fakeStore) InsertUsageEvent(context.Context, store.UsageEvent) error      { return nil }

// testRoute is a POST, write-scope, tx-class proxied route — registered by
// Router() from routes.All and forwarded to the ika upstream.
const testRoute = "/v1/dwallet/dkg/prepare"

func authedBundle(scopes, ipAllow []string) *store.AuthenticatedKey {
	return &store.AuthenticatedKey{
		User:   &store.User{ID: "user-1", Email: "u@example.com"},
		APIKey: &store.APIKey{ID: "key-1", UserID: "user-1", Scopes: scopes, IPAllowlist: ipAllow},
		Subscription: &store.Subscription{
			ID: "sub-1", UserID: "user-1", PlanCode: "pro", Status: "active",
			TokensLimit: 1_000_000,
		},
	}
}

// newTestServer wires a Server against the fake store + an httptest engine.
func newTestServer(t *testing.T, fs *fakeStore, engine http.Handler) (*Server, *httptest.Server) {
	t.Helper()
	eng := httptest.NewServer(engine)
	t.Cleanup(eng.Close)
	cfg := &config.Config{
		Env:                "development",
		Port:               "0",
		IkaUpstreamURL:     eng.URL,
		InternalAPIKey:     "internal-k",
		UpstreamTimeout:    5 * time.Second,
		DefaultRequestCost: 1,
	}
	ups, err := upstream.NewRegistryWithObserver(cfg, nil)
	if err != nil {
		t.Fatalf("upstream registry: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter, _ := ratelimit.New("", false, logger)
	srv := NewServer(Deps{
		Config:    cfg,
		Store:     fs,
		Limiter:   limiter,
		Pricer:    pricing.New(fs, 1, time.Minute, logger),
		Usage:     usage.NewRecorder(fs, logger),
		Upstreams: ups,
		Logger:    logger,
	})
	return srv, eng
}

func okEngine(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func postProxy(t *testing.T, h http.Handler, apiKey string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, testRoute, strings.NewReader(`{}`))
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProxy_MissingAPIKey(t *testing.T) {
	fs := &fakeStore{}
	srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
	rec := postProxy(t, srv.Router(), "", "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "missing_api_key") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestProxy_InvalidAPIKey(t *testing.T) {
	fs := &fakeStore{authErr: store.ErrNotFound}
	srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
	rec := postProxy(t, srv.Router(), "whatever", "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_api_key") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestProxy_NoSubscription(t *testing.T) {
	b := authedBundle([]string{"write"}, nil)
	b.Subscription = nil
	fs := &fakeStore{bundle: b}
	srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no_active_subscription") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestProxy_ScopeMissing(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"read"}, nil)} // route needs "write"
	srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "scope_missing") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&fs.consumed) != 0 {
		t.Fatal("must not charge when scope check fails")
	}
}

func TestProxy_HappyPath(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"write"}, nil)}
	srv, _ := newTestServer(t, fs, okEngine(200, `{"prepared":true}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"prepared":true}` {
		t.Fatalf("body not forwarded verbatim: %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Andromeda-Tokens-Cost"); got != "1" {
		t.Fatalf("X-Andromeda-Tokens-Cost = %q, want 1", got)
	}
	if rec.Header().Get("X-Andromeda-Tokens-Limit") != "1000000" {
		t.Fatalf("X-Andromeda-Tokens-Limit = %q", rec.Header().Get("X-Andromeda-Tokens-Limit"))
	}
	if rec.Header().Get("X-Andromeda-Upstream") != "ika" {
		t.Fatalf("X-Andromeda-Upstream = %q, want ika", rec.Header().Get("X-Andromeda-Upstream"))
	}
	if atomic.LoadInt32(&fs.consumed) != 1 || atomic.LoadInt32(&fs.refunded) != 0 {
		t.Fatalf("consumed=%d refunded=%d, want 1/0", fs.consumed, fs.refunded)
	}
}

func TestProxy_QuotaExceeded(t *testing.T) {
	fs := &fakeStore{
		bundle: authedBundle([]string{"write"}, nil),
		consumeFn: func(string, int) (*store.ConsumptionResult, error) {
			return nil, store.ErrQuotaExceeded
		},
	}
	srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), "quota_exceeded") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestProxy_UpstreamErrorRefunds(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"write"}, nil)}
	srv, _ := newTestServer(t, fs, okEngine(503, `{"error":"engine down"}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != 503 {
		t.Fatalf("code=%d, want 503 forwarded", rec.Code)
	}
	if atomic.LoadInt32(&fs.refunded) != 1 {
		t.Fatalf("refunded=%d, want 1 (5xx refunds)", fs.refunded)
	}
}

func TestProxy_4xxStaysCharged(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"write"}, nil)}
	srv, _ := newTestServer(t, fs, okEngine(422, `{"error":"bad input"}`))
	rec := postProxy(t, srv.Router(), "k", "")
	if rec.Code != 422 {
		t.Fatalf("code=%d, want 422 forwarded", rec.Code)
	}
	if atomic.LoadInt32(&fs.refunded) != 0 {
		t.Fatalf("refunded=%d, want 0 (4xx is caller's fault)", fs.refunded)
	}
}

func TestProxy_CircuitBreakerOpens(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"write"}, nil)}
	srv, _ := newTestServer(t, fs, okEngine(500, `boom`))
	router := srv.Router()
	// 5 consecutive 5xx trips the breaker.
	for i := 0; i < 5; i++ {
		if rec := postProxy(t, router, "k", ""); rec.Code != 500 {
			t.Fatalf("call %d: code=%d, want 500", i+1, rec.Code)
		}
	}
	// 6th call is short-circuited before the engine.
	rec := postProxy(t, router, "k", "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "upstream_circuit_open") {
		t.Fatalf("after trip: code=%d body=%q, want 503 upstream_circuit_open", rec.Code, rec.Body.String())
	}
	// Every attempt (incl. the short-circuit) refunds the charge.
	if atomic.LoadInt32(&fs.consumed) != 6 || atomic.LoadInt32(&fs.refunded) != 6 {
		t.Fatalf("consumed=%d refunded=%d, want 6/6", fs.consumed, fs.refunded)
	}
}

func TestProxy_IPAllowlist(t *testing.T) {
	t.Run("blocked IP", func(t *testing.T) {
		fs := &fakeStore{bundle: authedBundle([]string{"write"}, []string{"10.0.0.0/8"})}
		srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
		rec := postProxy(t, srv.Router(), "k", "1.2.3.4:5678")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "ip_not_allowed") {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})
	t.Run("allowed IP (incl. IPv6 in list)", func(t *testing.T) {
		fs := &fakeStore{bundle: authedBundle([]string{"write"}, []string{"10.0.0.0/8", "2001:db8::/32"})}
		srv, _ := newTestServer(t, fs, okEngine(200, `{}`))
		if rec := postProxy(t, srv.Router(), "k", "10.0.0.5:1234"); rec.Code != 200 {
			t.Fatalf("v4 allowed: code=%d", rec.Code)
		}
		if rec := postProxy(t, srv.Router(), "k", "[2001:db8:1:2::3]:443"); rec.Code != 200 {
			t.Fatalf("v6 allowed: code=%d", rec.Code)
		}
	})
}
