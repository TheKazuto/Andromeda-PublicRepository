package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

// Dispatcher tunables. P1.5 of the robustness plan: bigger batch + worker
// pool + lease-aware recovery so a 1k/s webhook burst clears without
// backlog and a dispatcher crash doesn't leave rows stuck in_flight.
//
// Override via env:
//
//	WEBHOOK_DISPATCHER_BATCH      — max rows claimed per tick (default 100)
//	WEBHOOK_DISPATCHER_TICK_MS    — claim cadence (default 1000)
//	WEBHOOK_DISPATCHER_WORKERS    — concurrent deliveries in flight (default 20)
//	WEBHOOK_DISPATCHER_LEASE_SEC  — lease duration (default 60)
//	WEBHOOK_RECOVER_TICK_SEC      — stuck-claim sweep cadence (default 30)
const (
	defaultMaxAttempts = 8
	defaultMaxBackoff  = 24 * time.Hour
)

var (
	dispatcherBatch    = envInt("WEBHOOK_DISPATCHER_BATCH", 100)
	dispatcherTick     = time.Duration(envInt("WEBHOOK_DISPATCHER_TICK_MS", 1000)) * time.Millisecond
	dispatcherWorkers  = envInt("WEBHOOK_DISPATCHER_WORKERS", 20)
	dispatcherLeaseSec = envInt("WEBHOOK_DISPATCHER_LEASE_SEC", 60)
	recoverTick        = time.Duration(envInt("WEBHOOK_RECOVER_TICK_SEC", 30)) * time.Second
	// Per-destination rate limit. Defaults are conservative — many
	// webhook receivers expect well below 50 req/s sustained. Operators
	// with cooperative receivers can raise via env.
	perEndpointRPS   = envInt("WEBHOOK_PER_ENDPOINT_RPS", 50)
	perEndpointBurst = envInt("WEBHOOK_PER_ENDPOINT_BURST", 100)
	// Idle endpoint limiters are evicted after this many seconds without
	// a delivery, keeping the map bounded under high tenant churn.
	endpointLimiterIdleSec = envInt("WEBHOOK_ENDPOINT_LIMITER_IDLE_SEC", 600)
)

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		_, err := fmt.Sscanf(v, "%d", &n)
		if err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// DispatcherMetrics is the minimum metrics surface the dispatcher uses.
// Lets us record `deliveries_total{outcome=...}` without depending on the
// gateway metrics package directly. Nil-safe via the recordOutcome helper.
type DispatcherMetrics interface {
	RecordDeliveryOutcome(outcome string)
	// RateLimitedTotal counts deliveries deferred because their
	// endpoint's per-destination bucket was exhausted. No labels — the
	// endpoint_id cardinality would balloon the series count.
	RecordWebhookRateLimited()
}

// Dispatcher pulls pending deliveries from the store, POSTs them with HMAC
// signatures, and reschedules with exponential backoff on failure.
//
// Concurrency model (P1.5):
//   - tick goroutine claims a batch and pushes each Delivery onto `jobs`.
//   - N worker goroutines drain `jobs` in parallel.
//   - sweeper goroutine reverts stuck in_flight rows whose lease expired.
//
// The pool size + tick + lease are env-tunable (see dispatcher.go top).
//
// Per-destination rate limit: each endpoint_id has its own token bucket
// (rate `perEndpointRPS`, burst `perEndpointBurst`). When a delivery
// can't acquire a token, it is put back to `pending` with a small
// backoff and another worker picks something else. This protects slow
// receivers from being overwhelmed by a burst on the gateway side.
type Dispatcher struct {
	store      *Store
	httpClient *http.Client
	logger     *slog.Logger
	urlGuard   *netsafety.Validator
	metrics    DispatcherMetrics

	maxAttempts int
	maxBackoff  time.Duration

	// claimOwner identifies this replica in the lease metadata so an
	// operator can correlate stuck rows back to a specific instance.
	claimOwner string

	// endpointLimiters holds a per-endpoint token bucket. The map grows
	// on first delivery to an endpoint and is pruned by janitor() every
	// 5 min — entries idle for `endpointLimiterIdleSec` are dropped.
	endpointLimitersMu sync.Mutex
	endpointLimiters   map[string]*endpointLimiter
}

type endpointLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewDispatcher(store *Store, logger *slog.Logger) *Dispatcher {
	owner := os.Getenv("RAILWAY_REPLICA_ID")
	if owner == "" {
		owner = uuid.NewString()
	}
	return &Dispatcher{
		store: store,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:           logger,
		urlGuard:         netsafety.New(netsafety.ModeProduction),
		maxAttempts:      defaultMaxAttempts,
		maxBackoff:       defaultMaxBackoff,
		claimOwner:       owner,
		endpointLimiters: map[string]*endpointLimiter{},
	}
}

// allowEndpoint consults the per-endpoint token bucket. Returns true when
// the delivery may proceed; false when it should be requeued.
func (d *Dispatcher) allowEndpoint(endpointID string) bool {
	d.endpointLimitersMu.Lock()
	defer d.endpointLimitersMu.Unlock()
	el, ok := d.endpointLimiters[endpointID]
	if !ok {
		el = &endpointLimiter{
			limiter: rate.NewLimiter(rate.Limit(perEndpointRPS), perEndpointBurst),
		}
		d.endpointLimiters[endpointID] = el
	}
	el.lastSeen = time.Now()
	return el.limiter.Allow()
}

// pruneEndpointLimiters drops entries idle longer than the configured
// window. Runs every 5 min via janitor().
func (d *Dispatcher) pruneEndpointLimiters() {
	cutoff := time.Now().Add(-time.Duration(endpointLimiterIdleSec) * time.Second)
	d.endpointLimitersMu.Lock()
	defer d.endpointLimitersMu.Unlock()
	for k, el := range d.endpointLimiters {
		if el.lastSeen.Before(cutoff) {
			delete(d.endpointLimiters, k)
		}
	}
}

// WithURLGuard overrides the SSRF guard used to validate delivery endpoints.
// Pass a ModeDevelopment validator in dev so localhost callbacks work; nil is
// ignored (keeps the safe ModeProduction default).
func (d *Dispatcher) WithURLGuard(g *netsafety.Validator) *Dispatcher {
	if g != nil {
		d.urlGuard = g
	}
	return d
}

// WithMetrics wires the metrics recorder. Returning *Dispatcher keeps the
// fluent main.go wiring style.
func (d *Dispatcher) WithMetrics(m DispatcherMetrics) *Dispatcher {
	d.metrics = m
	return d
}

func (d *Dispatcher) recordOutcome(outcome string) {
	if d.metrics != nil {
		d.metrics.RecordDeliveryOutcome(outcome)
	}
}

func (d *Dispatcher) recordRateLimited() {
	if d.metrics != nil {
		d.metrics.RecordWebhookRateLimited()
	}
}

// statusOutcome maps an HTTP status code to a coarse `outcome` label.
func statusOutcome(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "other"
	}
}

// Run blocks until ctx is cancelled. Three loops run in parallel:
//   - claim loop: claims a batch of deliveries every `dispatcherTick`,
//     pushes each Delivery into the `jobs` channel.
//   - N worker goroutines: drain `jobs` and call deliver().
//   - sweeper: every `recoverTick` reverts stuck in_flight rows whose
//     lease passed (crashed dispatcher recovery).
func (d *Dispatcher) Run(ctx context.Context) {
	d.logger.Info("webhook dispatcher started",
		"batch", dispatcherBatch, "tick", dispatcherTick.String(),
		"workers", dispatcherWorkers, "lease_sec", dispatcherLeaseSec,
		"recover_tick", recoverTick.String(), "owner", d.claimOwner)

	jobs := make(chan *Delivery, dispatcherBatch*2)
	var wg sync.WaitGroup

	// Worker pool.
	for i := 0; i < dispatcherWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dlv := range jobs {
				d.deliver(ctx, dlv)
			}
		}()
	}

	// Stuck-claim sweeper. Cheap: indexed UPDATE.
	sweepCtx, cancelSweep := context.WithCancel(ctx)
	defer cancelSweep()
	go d.recoverLoop(sweepCtx)
	// Prune idle endpoint limiters every 5 min to bound the map size
	// under high tenant churn.
	go d.endpointLimiterJanitor(sweepCtx)

	t := time.NewTicker(dispatcherTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			d.logger.Info("webhook dispatcher stopped")
			return
		case <-t.C:
			d.tick(ctx, jobs)
		}
	}
}

func (d *Dispatcher) tick(ctx context.Context, jobs chan<- *Delivery) {
	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	deliveries, err := d.store.ClaimDeliveries(claimCtx, dispatcherBatch, dispatcherLeaseSec, d.claimOwner)
	if err != nil {
		d.logger.Warn("claim deliveries failed", "err", err)
		return
	}
	for _, dlv := range deliveries {
		select {
		case jobs <- dlv:
		case <-ctx.Done():
			return
		}
	}
}

func (d *Dispatcher) endpointLimiterJanitor(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.pruneEndpointLimiters()
		}
	}
}

func (d *Dispatcher) recoverLoop(ctx context.Context) {
	t := time.NewTicker(recoverTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			n, err := d.store.RecoverStuck(sweepCtx)
			cancel()
			if err != nil {
				d.logger.Warn("recover stuck deliveries failed", "err", err)
				continue
			}
			if n > 0 {
				d.logger.Warn("recovered stuck webhook deliveries", "count", n)
			}
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, dlv *Delivery) {
	// Per-destination rate limit (cheap in-memory check before fetching
	// the endpoint or even touching the HTTP client). If the bucket is
	// empty, requeue with a short delay so another worker picks something
	// else; this drops the attempts counter back so we don't waste a
	// retry on a deferral.
	endpointKey := dlv.EndpointID.String()
	if !d.allowEndpoint(endpointKey) {
		d.recordRateLimited()
		// Small jittered delay: 200-700ms. Long enough that the token
		// bucket refills, short enough that legitimate traffic isn't
		// starved.
		delay := 200*time.Millisecond + time.Duration(dlv.ID[0])*2*time.Millisecond
		if err := d.store.RequeueWithDelay(ctx, dlv.ID, delay); err != nil {
			d.logger.Warn("requeue rate-limited delivery failed", "delivery_id", dlv.ID, "err", err)
		}
		return
	}
	endpoint, err := d.fetchEndpoint(ctx, dlv.EndpointID)
	if err != nil {
		d.logger.Warn("endpoint lookup failed", "delivery_id", dlv.ID, "err", err)
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, fmt.Sprintf("endpoint lookup: %v", err),
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
		if d.exhausted(dlv.Attempts) {
			d.recordOutcome("dead_letter")
		} else {
			d.recordOutcome("network_error")
		}
		return
	}
	if !endpoint.Active {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, "endpoint inactive", time.Now().Add(d.maxBackoff), true)
		d.recordOutcome("dead_letter")
		return
	}
	if err := d.urlGuard.ValidateDispatch(ctx, endpoint.URL); err != nil {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, "endpoint URL rejected by url guard",
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
		if d.exhausted(dlv.Attempts) {
			d.recordOutcome("dead_letter")
		} else {
			d.recordOutcome("network_error")
		}
		return
	}

	timestamp := time.Now().Unix()
	signed := fmt.Sprintf("%d.%s", timestamp, dlv.Payload)
	mac := hmac.New(sha256.New, []byte(endpoint.Secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL, bytes.NewReader(dlv.Payload))
	if err != nil {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, err.Error(),
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
		if d.exhausted(dlv.Attempts) {
			d.recordOutcome("dead_letter")
		} else {
			d.recordOutcome("network_error")
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Andromeda-Signature", fmt.Sprintf("t=%d,v1=%s", timestamp, sig))
	req.Header.Set("X-Andromeda-Event-Id", dlv.EventID.String())
	req.Header.Set("X-Andromeda-Event-Type", dlv.EventType)
	req.Header.Set("X-Andromeda-Delivery-Id", dlv.ID.String())
	req.Header.Set("X-Andromeda-Attempt", strconv.Itoa(dlv.Attempts))

	resp, err := d.httpClient.Do(req)
	if err != nil {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, err.Error(),
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
		if d.exhausted(dlv.Attempts) {
			d.recordOutcome("dead_letter")
		} else {
			d.recordOutcome("network_error")
		}
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := string(bodyBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = d.store.MarkDelivered(ctx, dlv.ID, resp.StatusCode, body)
		d.recordOutcome("2xx")
		return
	}
	_ = d.store.MarkFailed(ctx, dlv.ID, resp.StatusCode, body,
		time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
	if d.exhausted(dlv.Attempts) {
		d.recordOutcome("dead_letter")
	} else {
		d.recordOutcome(statusOutcome(resp.StatusCode))
	}
}

func (d *Dispatcher) backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	// 60s * 2^(attempts-1) capped at maxBackoff.
	exp := math.Pow(2, float64(attempts-1))
	dur := time.Duration(60*exp) * time.Second
	if dur > d.maxBackoff {
		return d.maxBackoff
	}
	return dur
}

func (d *Dispatcher) exhausted(attempts int) bool {
	return attempts >= d.maxAttempts
}

func (d *Dispatcher) fetchEndpoint(ctx context.Context, id [16]byte) (*Endpoint, error) {
	row := d.store.pool.QueryRow(ctx, `
		SELECT id, api_key_id, url, secret, events, active, created_at,
		       last_success_at, last_failure_at, failure_count
		FROM webhook_endpoints WHERE id = $1
	`, id)
	return scanEndpoint(row)
}
