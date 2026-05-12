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
	"strconv"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

const (
	defaultMaxAttempts = 8
	defaultMaxBackoff  = 24 * time.Hour
	dispatcherBatch    = 25
	dispatcherTick     = 5 * time.Second
)

// Dispatcher pulls pending deliveries from the store, POSTs them with HMAC
// signatures, and reschedules with exponential backoff on failure.
type Dispatcher struct {
	store      *Store
	httpClient *http.Client
	logger     *slog.Logger
	urlGuard   *netsafety.Validator

	maxAttempts int
	maxBackoff  time.Duration
}

func NewDispatcher(store *Store, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		store: store,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:      logger,
		urlGuard:    netsafety.New(netsafety.ModeProduction),
		maxAttempts: defaultMaxAttempts,
		maxBackoff:  defaultMaxBackoff,
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

// Run blocks until ctx is cancelled, ticking every `dispatcherTick`.
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(dispatcherTick)
	defer t.Stop()
	d.logger.Info("webhook dispatcher started")
	for {
		select {
		case <-ctx.Done():
			d.logger.Info("webhook dispatcher stopped")
			return
		case <-t.C:
			d.tick(ctx)
		}
	}
}

func (d *Dispatcher) tick(ctx context.Context) {
	deliveries, err := d.store.ClaimDeliveries(ctx, dispatcherBatch)
	if err != nil {
		d.logger.Warn("claim deliveries failed", "err", err)
		return
	}
	for _, dlv := range deliveries {
		d.deliver(ctx, dlv)
	}
}

func (d *Dispatcher) deliver(ctx context.Context, dlv *Delivery) {
	endpoint, err := d.fetchEndpoint(ctx, dlv.EndpointID)
	if err != nil {
		d.logger.Warn("endpoint lookup failed", "delivery_id", dlv.ID, "err", err)
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, fmt.Sprintf("endpoint lookup: %v", err),
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
		return
	}
	if !endpoint.Active {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, "endpoint inactive", time.Now().Add(d.maxBackoff), true)
		return
	}
	if err := d.urlGuard.ValidateDispatch(ctx, endpoint.URL); err != nil {
		_ = d.store.MarkFailed(ctx, dlv.ID, 0, "endpoint URL rejected by url guard",
			time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
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
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := string(bodyBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = d.store.MarkDelivered(ctx, dlv.ID, resp.StatusCode, body)
		return
	}
	_ = d.store.MarkFailed(ctx, dlv.ID, resp.StatusCode, body,
		time.Now().Add(d.backoff(dlv.Attempts)), d.exhausted(dlv.Attempts))
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
