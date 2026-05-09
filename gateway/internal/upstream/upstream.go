package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/sony/gobreaker/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

// ErrCircuitOpen is returned by Allow when the upstream's breaker has
// tripped. Callers must short-circuit with 503 Service Unavailable.
var ErrCircuitOpen = errors.New("circuit breaker open")

// breakerSettings controls the trip threshold and recovery window.
// Tuned conservatively: open after 5 consecutive failures (or 50%
// failure rate over 20 requests), stay open for 30 seconds, then
// half-open with one probe request before re-closing.
func breakerSettings(name string, onTrip func()) gobreaker.Settings {
	return gobreaker.Settings{
		Name:        name,
		MaxRequests: 1,
		Interval:    60 * time.Second, // counter window
		Timeout:     30 * time.Second, // open → half-open delay
		ReadyToTrip: func(c gobreaker.Counts) bool {
			if c.ConsecutiveFailures >= 5 {
				return true
			}
			if c.Requests >= 20 {
				ratio := float64(c.TotalFailures) / float64(c.Requests)
				return ratio >= 0.5
			}
			return false
		},
		OnStateChange: func(_ string, from, to gobreaker.State) {
			if to == gobreaker.StateOpen && onTrip != nil {
				onTrip()
			}
		},
	}
}

// Target represents a configured upstream engine.
type Target struct {
	Name       string
	BaseURL    *url.URL
	AuthHeader string // "X-Api-Key" or "X-Internal-Key"
	AuthValue  string
	Proxy      *httputil.ReverseProxy
	client     *http.Client
	breaker    *gobreaker.CircuitBreaker[*http.Response]
}

// State exposes the current breaker state (closed/open/half-open). Used
// by /health/ready and /metrics. Returns "closed" for unconfigured targets.
func (t *Target) State() string {
	if t == nil || t.breaker == nil {
		return "closed"
	}
	switch t.breaker.State() {
	case gobreaker.StateOpen:
		return "open"
	case gobreaker.StateHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// Allow checks the breaker. When open, returns ErrCircuitOpen so the
// proxy handler can fast-fail with 503 before involving the upstream.
// Use immediately before invoking Proxy.ServeHTTP.
func (t *Target) Allow() error {
	if t == nil || t.breaker == nil {
		return nil
	}
	if t.breaker.State() == gobreaker.StateOpen {
		return ErrCircuitOpen
	}
	return nil
}

// MarkResult feeds the breaker after a proxy call completes. Treats
// 5xx and transport errors as failures; everything else (including 4xx
// — that's the caller's fault, not the upstream's) as success.
func (t *Target) MarkResult(status int, err error) {
	if t == nil || t.breaker == nil {
		return
	}
	if err != nil || status >= 500 {
		// Use Execute to surface the failure to the breaker. The
		// returned bool from the action determines success.
		_, _ = t.breaker.Execute(func() (*http.Response, error) {
			return nil, errors.New("upstream failure")
		})
		return
	}
	_, _ = t.breaker.Execute(func() (*http.Response, error) {
		return nil, nil
	})
}

// MaxCallResponseBytes caps the payload accepted from an upstream when
// invoked via Call(). Picked to comfortably fit any expected JSON payload
// (presigns lists, signed-tx blobs) while still bounding memory.
const MaxCallResponseBytes = 8 << 20 // 8 MiB

// ErrUpstreamNotConfigured is returned by Call when the target has no
// BaseURL set (development with the env var missing).
var ErrUpstreamNotConfigured = errors.New("upstream not configured")

// Registry holds the ika and encrypt upstreams.
type Registry struct {
	Ika     *Target
	Encrypt *Target
	Timeout time.Duration
}

// TripObserver is called whenever an upstream breaker transitions to
// the OPEN state — used by metrics + alerting.
type TripObserver func(upstreamName string)

func NewRegistry(cfg *config.Config) (*Registry, error) {
	return NewRegistryWithObserver(cfg, nil)
}

// NewRegistryWithObserver is the metrics-aware constructor. obs is invoked
// from the breaker's OnStateChange callback whenever a target trips open.
func NewRegistryWithObserver(cfg *config.Config, obs TripObserver) (*Registry, error) {
	ika, err := newTarget(routes.UpstreamIka, cfg.IkaUpstreamURL, "X-Api-Key", cfg.InternalAPIKey, cfg.UpstreamTimeout, obs)
	if err != nil {
		return nil, fmt.Errorf("ika upstream: %w", err)
	}
	enc, err := newTarget(routes.UpstreamEncrypt, cfg.EncryptUpstreamURL, "X-Internal-Key", cfg.InternalAPIKey, cfg.UpstreamTimeout, obs)
	if err != nil {
		return nil, fmt.Errorf("encrypt upstream: %w", err)
	}
	return &Registry{Ika: ika, Encrypt: enc, Timeout: cfg.UpstreamTimeout}, nil
}

// Get returns the target by upstream name. Returns nil if unknown.
func (r *Registry) Get(name string) *Target {
	switch name {
	case routes.UpstreamIka:
		return r.Ika
	case routes.UpstreamEncrypt:
		return r.Encrypt
	}
	return nil
}

func newTarget(name, baseURL, authHeader, authValue string, timeout time.Duration, obs TripObserver) (*Target, error) {
	if baseURL == "" {
		// Allow empty in development — handler will return 502 if hit.
		return &Target{Name: name, AuthHeader: authHeader, AuthValue: authValue}, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	// otelhttp.NewTransport propagates the W3C Trace Context to the
	// upstream — when tracing is disabled (no OTEL_EXPORTER endpoint)
	// it's a zero-cost pass-through.
	baseTransport := &http.Transport{
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   32,
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(baseTransport),
	}
	t := &Target{
		Name:       name,
		BaseURL:    u,
		AuthHeader: authHeader,
		AuthValue:  authValue,
		client:     httpClient,
	}
	t.breaker = gobreaker.NewCircuitBreaker[*http.Response](
		breakerSettings(name, func() {
			if obs != nil {
				obs(name)
			}
		}),
	)

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			// Preserve original Path-after-rewrite via context (set by proxy handler).
			if rewritten := pr.Out.Header.Get("X-Andromeda-Upstream-Path"); rewritten != "" {
				pr.Out.URL.Path = rewritten
				pr.Out.URL.RawPath = ""
				pr.Out.Header.Del("X-Andromeda-Upstream-Path")
			}
			// Strip any caller auth — gateway alone authenticates with the upstream.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-Api-Key")
			pr.Out.Header.Del("X-Internal-Key")
			if authHeader != "" && authValue != "" {
				pr.Out.Header.Set(authHeader, authValue)
			}
			pr.Out.Host = u.Host
		},
		Transport: otelhttp.NewTransport(&http.Transport{
			ResponseHeaderTimeout: timeout,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   32,
		}),
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Andromeda-Upstream", name)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, `{"error":"bad gateway"}`, http.StatusBadGateway)
		},
	}
	t.Proxy = rp
	return t, nil
}

// CallResult is the structured response from an in-process upstream call.
type CallResult struct {
	StatusCode int
	Body       []byte
	// ContentType echoes the upstream's Content-Type header. Empty if absent.
	ContentType string
}

// Call performs an in-process HTTP request against the upstream. This is
// the non-proxy path used by MCP tool handlers (and any other internal
// caller that needs to read the response body before forwarding).
//
// The auth header configured on the target is set automatically. Non-2xx
// responses are returned without error — the caller decides how to handle
// them. A nil error with StatusCode == 0 indicates the target is not
// configured (BaseURL empty); ErrUpstreamNotConfigured is returned in that
// case.
func (t *Target) Call(ctx context.Context, method, path string, query url.Values, body []byte) (*CallResult, error) {
	if t == nil || t.BaseURL == nil {
		return nil, fmt.Errorf("%w: %s", ErrUpstreamNotConfigured, t.safeName())
	}

	u := *t.BaseURL
	u.Path = singleSlashJoin(u.Path, path)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if t.AuthHeader != "" && t.AuthValue != "" {
		req.Header.Set(t.AuthHeader, t.AuthValue)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	client := t.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream %s call: %w", t.Name, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxCallResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}
	return &CallResult{
		StatusCode:  resp.StatusCode,
		Body:        respBody,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func (t *Target) safeName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Name == "" {
		return "<unnamed>"
	}
	return t.Name
}

// singleSlashJoin joins a base path and a sub-path with exactly one slash
// between them. Both empty inputs return "/".
func singleSlashJoin(a, b string) string {
	a = strings.TrimRight(a, "/")
	b = strings.TrimLeft(b, "/")
	switch {
	case a == "" && b == "":
		return "/"
	case a == "":
		return "/" + b
	case b == "":
		return a
	default:
		return a + "/" + b
	}
}
