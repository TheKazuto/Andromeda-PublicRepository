package lifi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"

	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// maxResponseBytes bounds a LI.FI response body. Quotes with many included
// steps are large but never approach this; it just stops a hostile/buggy
// upstream from exhausting memory.
const maxResponseBytes = 8 << 20 // 8 MiB

// ErrBackpressure is returned when the local limiter (or a server-signalled
// rate-limit window) says we must back off before calling LI.FI again. The
// handler maps it to 429/503 with a Retry-After.
var ErrBackpressure = errors.New("lifi backpressure")

// ErrUpstream is returned for a non-2xx LI.FI response. RetryAfter is set when
// the upstream signalled a cool-down.
type ErrUpstream struct {
	StatusCode int
	RetryAfter time.Duration
	Body       string
}

func (e *ErrUpstream) Error() string {
	return fmt.Sprintf("lifi status %d", e.StatusCode)
}

// Client is the LI.FI HTTP client: pooled transport, circuit breaker, local
// backpressure, and automatic integrator-fee injection.
type Client struct {
	baseURL    string
	apiKey     string
	integrator string
	feeBps     int

	http    *http.Client
	breaker *gobreaker.CircuitBreaker[*callResult]
	metrics *metrics.Metrics
	logger  *slog.Logger

	bp *backpressure

	rpcOnce  sync.Once
	rpcCache *RPCCache
}

type callResult struct {
	status int
	body   []byte
}

// Options configures the client.
type Options struct {
	BaseURL    string
	APIKey     string
	Integrator string
	FeeBps     int
	Timeout    time.Duration
	Metrics    *metrics.Metrics
	Logger     *slog.Logger
}

func New(opts Options) *Client {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     200,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	c := &Client{
		baseURL:    opts.BaseURL,
		apiKey:     opts.APIKey,
		integrator: opts.Integrator,
		feeBps:     opts.FeeBps,
		http:       &http.Client{Timeout: opts.Timeout, Transport: transport},
		metrics:    opts.Metrics,
		logger:     opts.Logger,
		bp:         newBackpressure(),
	}
	c.breaker = gobreaker.NewCircuitBreaker[*callResult](gobreaker.Settings{
		Name:        "lifi",
		MaxRequests: 1,
		Interval:    60 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
		OnStateChange: func(_ string, _, to gobreaker.State) {
			if c.metrics != nil {
				c.metrics.LifiBreakerState.Set(breakerStateValue(to))
			}
		},
	})
	return c
}

// FeeDecimal renders the configured integrator fee as a decimal string without
// using float (e.g. 30 bps → "0.0030"). Empty when no fee is configured.
func (c *Client) FeeDecimal() string {
	if c.feeBps <= 0 {
		return ""
	}
	return fmt.Sprintf("%d.%04d", c.feeBps/10000, c.feeBps%10000)
}

// get performs a LI.FI GET against `path` with `query`, gated by backpressure
// and the breaker. endpoint is the short label used for metrics/backpressure
// (e.g. "quote", "chains").
func (c *Client) get(ctx context.Context, endpoint, path string, query url.Values) ([]byte, error) {
	if wait, ok := c.bp.shouldWait(endpoint); ok {
		if c.metrics != nil {
			c.metrics.LifiBackpressure.WithLabelValues(endpoint).Inc()
		}
		return nil, fmt.Errorf("%w: retry after %s", ErrBackpressure, wait)
	}

	start := time.Now()
	res, err := c.breaker.Execute(func() (*callResult, error) {
		return c.doGet(ctx, path, query)
	})
	if c.metrics != nil {
		c.metrics.LifiRequestDuration.WithLabelValues(endpoint).Observe(time.Since(start).Seconds())
	}

	if err != nil {
		c.markResult(endpoint, "error")
		return nil, err
	}
	if res.status >= 200 && res.status < 300 {
		c.markResult(endpoint, "ok")
		return res.body, nil
	}
	// Non-2xx: surface a typed error and feed backpressure on 429/503.
	c.markResult(endpoint, "upstream_error")
	return nil, &ErrUpstream{StatusCode: res.status, Body: truncate(res.body, 256)}
}

func (c *Client) doGet(ctx context.Context, path string, query url.Values) (*callResult, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("x-lifi-api-key", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lifi request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read lifi body: %w", err)
	}

	// Update backpressure from rate-limit signals.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		c.bp.penalize("", retryAfterFrom(resp.Header))
	}

	// A non-2xx is NOT a breaker failure unless it's 5xx — a 4xx is the
	// caller's fault (bad token/chain), not an upstream outage.
	if resp.StatusCode >= 500 {
		return &callResult{status: resp.StatusCode, body: body}, fmt.Errorf("lifi 5xx: %d", resp.StatusCode)
	}
	return &callResult{status: resp.StatusCode, body: body}, nil
}

func (c *Client) markResult(endpoint, result string) {
	if c.metrics != nil {
		c.metrics.LifiRequestTotal.WithLabelValues(endpoint, result).Inc()
	}
}

// BreakerOpen reports whether the LI.FI breaker is currently open (used by
// readiness).
func (c *Client) BreakerOpen() bool {
	return c.breaker.State() == gobreaker.StateOpen
}

func breakerStateValue(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateOpen:
		return 2
	case gobreaker.StateHalfOpen:
		return 1
	default:
		return 0
	}
}

func retryAfterFrom(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	if v := h.Get("RateLimit-Reset"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 5 * time.Second // conservative default cool-down
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n])
}

// backpressure tracks a per-endpoint "do not call before" timestamp. A global
// penalty (empty key) covers a server-wide 429.
type backpressure struct {
	mu          sync.Mutex
	nextAllowed map[string]time.Time
}

func newBackpressure() *backpressure {
	return &backpressure{nextAllowed: make(map[string]time.Time)}
}

func (b *backpressure) shouldWait(endpoint string) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for _, key := range []string{"", endpoint} {
		if t, ok := b.nextAllowed[key]; ok && now.Before(t) {
			return time.Until(t), true
		}
	}
	return 0, false
}

func (b *backpressure) penalize(endpoint string, d time.Duration) {
	if d <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextAllowed[endpoint] = time.Now().Add(d)
}
