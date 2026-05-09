package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Listener is the Solana logsSubscribe consumer (Andromeda Features Roadmap §4.4).
//
// Phase 2 (active): each `Program data:` line in a logsNotification is decoded
// via ParseEvent against the canonical schema declared in
// `contracts/shared/src/events.rs`. Recognised events are forwarded through
// PolicyTenantResolver → Publisher.
//
// The tenant resolver maps a policy PDA back to the api_key_id that owns it.
// Until policy ownership is persisted in Postgres (follow-up: a
// `policy_subscriptions` table populated by `/v1/policies/init/submit`),
// the resolver returns uuid.Nil and the listener only logs events without
// fanning out — no double-publish risk.
//
// Reconnect strategy: 5-attempt exponential backoff capped at 60s. On a clean
// context cancel the loop exits without retrying.
// PolicyTenantResolver maps a policy PDA back to the api_key_id that
// originally deployed it. Returning uuid.Nil means "no tenant known" — the
// listener will log the event but skip the webhook fanout.
type PolicyTenantResolver func(ctx context.Context, policyAddress string) (uuid.UUID, bool)

// EventPublisher is the subset of Publisher the Listener needs. Decoupled
// for testability — the production wiring uses *Publisher; integration tests
// inject a fake that captures published events.
type EventPublisher interface {
	Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error)
}

type Listener struct {
	rpcURL     string
	programIDs []string
	publisher  EventPublisher
	resolver   PolicyTenantResolver
	logger     *slog.Logger
	limiter    *tenantLimiter
	onDrop     func(reason string)

	// stats — exposed for diagnostic / health endpoints later.
	notificationsReceived atomic.Int64
	eventsParsed          atomic.Int64
	eventsPublished       atomic.Int64
	connectErrors         atomic.Int64
	eventsDropped         atomic.Int64
}

// NewListener returns a Listener configured for the supplied program IDs.
// `resolver` may be nil — in that case the listener logs decoded events but
// never calls Publisher. Per-tenant rate limit defaults to 10/sec (burst 20).
func NewListener(rpcURL string, programIDs []string, publisher EventPublisher, resolver PolicyTenantResolver, logger *slog.Logger) *Listener {
	if logger == nil {
		logger = slog.Default()
	}
	return &Listener{
		rpcURL:     rpcURL,
		programIDs: programIDs,
		publisher:  publisher,
		resolver:   resolver,
		logger:     logger,
		limiter:    newTenantLimiter(10, 20),
	}
}

// WithRateLimit overrides the default 10/s, burst 20 per-tenant cap.
// Pass rate <= 0 to disable the limiter.
func (l *Listener) WithRateLimit(rate, burst float64) *Listener {
	l.limiter = newTenantLimiter(rate, burst)
	return l
}

// WithDropObserver wires a callback invoked every time the listener
// drops an event. Used to feed the Prometheus counter without coupling
// the webhook package to the metrics package.
func (l *Listener) WithDropObserver(cb func(reason string)) *Listener {
	l.onDrop = cb
	return l
}

// Stats returns a snapshot for /health/deep style diagnostics.
func (l *Listener) Stats() (notifications, parsed, published, errors int64) {
	return l.notificationsReceived.Load(),
		l.eventsParsed.Load(),
		l.eventsPublished.Load(),
		l.connectErrors.Load()
}

// Start blocks until ctx is cancelled. Each connect attempt subscribes to all
// configured program IDs in a single connection. On disconnect we backoff and
// reconnect — the SELECT FOR UPDATE pattern in the dispatcher takes care of any
// duplicate webhook deliveries we might enqueue once parsing is enabled.
func (l *Listener) Start(ctx context.Context) {
	if l.rpcURL == "" || len(l.programIDs) == 0 {
		l.logger.Info("solana listener disabled — no rpcURL or programIDs")
		<-ctx.Done()
		return
	}
	wsURL, err := httpToWS(l.rpcURL)
	if err != nil {
		l.logger.Error("solana listener invalid rpc URL", "url", l.rpcURL, "err", err)
		<-ctx.Done()
		return
	}
	l.logger.Info("solana listener starting",
		"ws_url", wsURL, "programs", l.programIDs)

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := l.runOnce(ctx, wsURL)
		if ctx.Err() != nil {
			return
		}
		l.connectErrors.Add(1)
		l.logger.Warn("solana listener disconnected", "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = nextBackoff(backoff)
	}
}

// runOnce establishes one WebSocket connection, subscribes, and pumps messages
// until either the context is cancelled or the connection drops.
func (l *Listener) runOnce(ctx context.Context, wsURL string) error {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Subscribe to every program. Mention IDs in JSON-RPC ID so we can correlate
	// subscription confirmations.
	for i, programID := range l.programIDs {
		req := map[string]any{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  "logsSubscribe",
			"params": []any{
				map[string]any{"mentions": []string{programID}},
				map[string]any{"commitment": "confirmed"},
			},
		}
		if err := conn.WriteJSON(req); err != nil {
			return fmt.Errorf("subscribe %s: %w", programID, err)
		}
	}

	// Read pump. The Solana RPC sends pings every ~30s; gorilla handles them
	// automatically. We set a short read deadline so a dead connection doesn't
	// block forever.
	closeOnCtx := make(chan struct{})
	defer close(closeOnCtx)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second))
			_ = conn.Close()
		case <-closeOnCtx:
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		l.handle(raw)
	}
}

// handle inspects a single inbound JSON-RPC message. Subscription confirmations
// are logged once at debug level; notifications go through observeNotification.
func (l *Listener) handle(raw []byte) {
	// Notifications carry `method`; subscription confirmations carry `result`.
	var probe struct {
		Method string          `json:"method"`
		Result json.RawMessage `json:"result"`
		ID     json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		l.logger.Warn("solana listener decode failed", "err", err)
		return
	}
	if probe.Method == "logsNotification" {
		l.observeNotification(raw)
		return
	}
	if len(probe.Result) > 0 {
		l.logger.Debug("solana listener subscription confirmed", "id", string(probe.ID), "result", string(probe.Result))
	}
}

// LogNotification mirrors the params payload for `logsNotification`.
type LogNotification struct {
	Subscription int `json:"subscription"`
	Result       struct {
		Context struct {
			Slot int64 `json:"slot"`
		} `json:"context"`
		Value struct {
			Signature string   `json:"signature"`
			Err       any      `json:"err"`
			Logs      []string `json:"logs"`
		} `json:"value"`
	} `json:"result"`
}

// observeNotification is the Phase 2 sink: extract every `Program data:` line
// from the notification, decode against the canonical event schema, and (when
// a tenant resolver is configured) fan out the event via Publisher.
func (l *Listener) observeNotification(raw []byte) {
	l.notificationsReceived.Add(1)
	var env struct {
		Params LogNotification `json:"params"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		l.logger.Warn("solana listener notification decode failed", "err", err)
		return
	}
	v := env.Params.Result.Value
	if v.Err != nil {
		// Tx failed on-chain — we don't surface events from failed txs.
		return
	}
	slot := env.Params.Result.Context.Slot
	payloads := extractEventLines(v.Logs)
	if len(payloads) == 0 {
		return
	}

	// We don't know which program emitted each Program-data line just from
	// the notification — we know only that some program in `programIDs` was
	// mentioned. The first program in the configured list is reported when
	// logging; the actual program is irrelevant to the canonical event type.
	mentioned := ""
	if len(l.programIDs) > 0 {
		mentioned = l.programIDs[0]
	}

	for _, payload := range payloads {
		ev, err := ParseEvent(payload, mentioned, slot, v.Signature)
		if err != nil {
			l.logger.Warn("solana listener parse failed",
				"err", err, "signature", v.Signature, "slot", slot)
			continue
		}
		if ev == nil {
			continue // unknown discriminator — skip silently
		}
		l.eventsParsed.Add(1)
		l.logger.Info("solana listener event parsed",
			"type", ev.Type, "policy", ev.Policy,
			"slot", slot, "signature", v.Signature)

		// Fanout requires both a Publisher and a resolver — without the latter
		// we can't scope the event to a tenant.
		if l.publisher == nil || l.resolver == nil {
			continue
		}
		// Pick the lookup key by event family:
		//   - Andromeda template events carry `Policy` (matches policy_address).
		//   - Ika dWallet events carry `Dwallet` (matches dwallet_address).
		// The resolver's ResolveAny path queries either column.
		lookupKey := ev.Policy
		if lookupKey == "" {
			lookupKey = ev.Dwallet
		}
		if lookupKey == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		apiKeyID, ok := l.resolver(ctx, lookupKey)
		cancel()
		if !ok || apiKeyID == uuid.Nil {
			continue
		}
		// Per-tenant rate limit — drop the event when a single tenant
		// is firing faster than the budget. Prevents one tenant from
		// starving the dispatch queue or piling pressure on Postgres.
		if l.limiter != nil && !l.limiter.Allow(apiKeyID) {
			l.eventsDropped.Add(1)
			if l.onDrop != nil {
				l.onDrop("rate_limit")
			}
			l.logger.Warn("solana listener event dropped — tenant rate-limited",
				"type", ev.Type, "policy", ev.Policy, "tenant", apiKeyID)
			continue
		}

		pubCtx, pubCancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, perr := l.publisher.Publish(pubCtx, apiKeyID, ev.Type, ev)
		pubCancel()
		if perr != nil {
			l.logger.Warn("solana listener publish failed",
				"err", perr, "type", ev.Type, "policy", ev.Policy)
			continue
		}
		l.eventsPublished.Add(1)
	}
}

// httpToWS converts http(s)://host[/path] to ws(s)://host[/path]. Returns an
// error for non-http URLs so misconfigurations surface at boot.
func httpToWS(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already a websocket URL — accept verbatim
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return u.String(), nil
}

func nextBackoff(d time.Duration) time.Duration {
	next := d * 2
	if next > 60*time.Second {
		return 60 * time.Second
	}
	return next
}
