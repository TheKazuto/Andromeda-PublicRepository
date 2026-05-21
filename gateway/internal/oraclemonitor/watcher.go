package oraclemonitor

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// EventPublisher is the subset of webhooks.Publisher the monitor needs. Same
// shape as futuresign.EventPublisher so the gateway's shared publisher
// satisfies both.
type EventPublisher interface {
	Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error)
}

// WatcherOptions configures the price-trigger monitor loop.
type WatcherOptions struct {
	Store     *Store
	Prices    LatestPriceProvider
	Firer     Firer
	Publisher EventPublisher // optional
	Metrics   Metrics        // optional (nil disables emission)
	Cluster   string
	Logger    *slog.Logger

	// Tick is how often the monitor scans armed triggers and reads Hermes.
	// Defaults to 10s.
	Tick time.Duration
	// ExpiryTick is how often overdue triggers are reaped. Defaults to 60s.
	ExpiryTick time.Duration
	// BatchLimit caps how many armed triggers are evaluated per tick.
	// Defaults to 500.
	BatchLimit int
}

// Watcher is the leader-elected managed keeper: it reads live Pyth prices from
// Hermes and fires the pre-built request_signature when a trigger's band is
// satisfied. The on-chain dispatch re-validates the real price, so the monitor
// is an untrusted trigger (it can never forge — only release a pre-committed
// message when the on-chain rule would already pass).
type Watcher struct {
	store     *Store
	prices    LatestPriceProvider
	firer     Firer
	publisher EventPublisher
	metrics   Metrics
	cluster   string
	tick      time.Duration
	expiry    time.Duration
	batch     int
	logger    *slog.Logger
}

// NewWatcher validates options and returns a Watcher.
func NewWatcher(o WatcherOptions) *Watcher {
	if o.Tick <= 0 {
		o.Tick = 10 * time.Second
	}
	if o.ExpiryTick <= 0 {
		o.ExpiryTick = 60 * time.Second
	}
	if o.BatchLimit <= 0 {
		o.BatchLimit = 500
	}
	if o.Cluster == "" {
		o.Cluster = "devnet"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Watcher{
		store:     o.Store,
		prices:    o.Prices,
		firer:     o.Firer,
		publisher: o.Publisher,
		metrics:   o.Metrics,
		cluster:   o.Cluster,
		tick:      o.Tick,
		expiry:    o.ExpiryTick,
		batch:     o.BatchLimit,
		logger:    o.Logger,
	}
}

// Start runs the monitor + expiry loops until ctx is cancelled. Intended to be
// wrapped by a leader.Runner so exactly one replica drives it (the ClaimByID
// atomic transition is defence-in-depth on top of that).
func (w *Watcher) Start(ctx context.Context) {
	go w.runExpiryLoop(ctx)
	ticker := time.NewTicker(w.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tickOnce(ctx)
		}
	}
}

func (w *Watcher) mErr(stage string) {
	if w.metrics != nil {
		w.metrics.RecordOracleMonitorError(stage)
	}
}

func (w *Watcher) tickOnce(ctx context.Context) {
	now := time.Now().UTC()
	triggers, err := w.store.ListActiveArmed(ctx, w.cluster, w.batch, now)
	if err != nil {
		w.logger.Warn("oracle monitor: list active armed failed", "err", err)
		w.mErr("tick")
		return
	}
	if len(triggers) == 0 {
		return
	}

	// Distinct feed ids → one Hermes batch read.
	seen := make(map[string]struct{}, len(triggers))
	feedIDs := make([]string, 0, len(triggers))
	for _, t := range triggers {
		if _, ok := seen[t.PythFeedIDHex]; ok {
			continue
		}
		seen[t.PythFeedIDHex] = struct{}{}
		feedIDs = append(feedIDs, t.PythFeedIDHex)
	}
	prices, err := w.prices.LatestPrices(ctx, feedIDs)
	if err != nil {
		w.logger.Warn("oracle monitor: hermes read failed", "err", err)
		w.mErr("hermes")
		return
	}

	for _, t := range triggers {
		if ctx.Err() != nil {
			return
		}
		price, ok := prices[t.PythFeedIDHex]
		if !ok {
			continue // no live price for this feed this tick — try next tick
		}
		if !inBand(price, t.Min1e8, t.Max1e8, t.HysteresisBps) {
			// Record only on a real price change to avoid write amplification.
			if t.LastPrice1e8 == nil || *t.LastPrice1e8 != price {
				if rerr := w.store.RecordCheck(ctx, t.ID, price); rerr != nil {
					w.logger.Warn("oracle monitor: record check failed", "trigger", t.ID, "err", rerr)
				}
			}
			continue
		}
		// In band → atomically claim (armed → firing) so no replica / re-scan
		// double-fires, then fire.
		claimed, err := w.store.ClaimByID(ctx, t.ID, price)
		if err != nil {
			w.logger.Warn("oracle monitor: claim failed", "trigger", t.ID, "err", err)
			w.mErr("claim")
			continue
		}
		if !claimed {
			continue // someone else took it
		}
		w.fire(ctx, t, price)
	}
}

func (w *Watcher) fire(ctx context.Context, t *PriceTrigger, price int64) {
	w.logger.Info("oracle price trigger firing",
		"trigger", t.ID, "feed", t.PythFeedIDHex, "price_1e8", price)
	if w.firer == nil {
		_ = w.store.MarkFailed(ctx, t.ID, "firer not configured")
		if w.metrics != nil {
			w.metrics.RecordOracleTriggerFire("failed")
		}
		return
	}
	txSig, err := w.firer.FireRequestSignature(ctx, t.RequestSignaturePayload)
	if err != nil {
		if merr := w.store.MarkFailed(ctx, t.ID, err.Error()); merr != nil {
			w.logger.Warn("oracle monitor: mark failed errored", "trigger", t.ID, "err", merr)
		}
		w.logger.Warn("oracle price trigger fire failed", "trigger", t.ID, "err", err)
		if w.metrics != nil {
			w.metrics.RecordOracleTriggerFire("failed")
		}
		return
	}
	// The tx landed on-chain → count it as a fire regardless of the DB write
	// below (the on-chain MessageApproval PDA makes a re-fire of the same
	// message a no-op, so this is never a double-sign).
	if w.metrics != nil {
		w.metrics.RecordOracleTriggerFire("fired")
	}
	if err := w.store.MarkFired(ctx, t.ID, txSig); err != nil {
		// The request_signature already landed; only the DB record failed.
		// Surface loudly WITH the signature so an operator can reconcile — the
		// reaper would otherwise relabel this real fire as `failed` after the
		// stuck-firing timeout.
		w.logger.Error("oracle monitor: tx landed but mark-fired failed (manual reconcile)",
			"trigger", t.ID, "tx_signature", txSig, "err", err)
		return
	}
	if w.publisher != nil {
		_, perr := w.publisher.Publish(ctx, t.APIKeyID, "oracle_trigger.fired", map[string]any{
			"trigger_id":      t.ID.String(),
			"dwallet_address": t.DWalletAddress,
			"feed_id_hex":     t.PythFeedIDHex,
			"price_1e8":       price,
			"tx_signature":    txSig,
		})
		if perr != nil {
			w.logger.Warn("oracle monitor: publish fired failed", "trigger", t.ID, "err", perr)
		}
	}
}

// stuckFiringTimeout is how long a trigger may sit in 'firing' before the reaper
// gives up on it. A normal fire (ClaimByID → SignAndSend, no confirmation wait)
// is sub-second, so 5 minutes only ever catches a crashed worker.
const stuckFiringTimeout = 5 * time.Minute

func (w *Watcher) runExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(w.expiry)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ids, err := w.store.ExpireOverdue(ctx, time.Now().UTC())
			if err != nil {
				w.logger.Warn("oracle monitor: expire overdue failed", "err", err)
			} else {
				if w.metrics != nil && len(ids) > 0 {
					w.metrics.RecordOracleTriggerExpired(len(ids))
				}
				for _, id := range ids {
					if w.publisher != nil {
						_, _ = w.publisher.Publish(ctx, uuid.Nil, "oracle_trigger.expired", map[string]any{
							"trigger_id": id.String(),
						})
					}
				}
			}
			// Rescue triggers stuck in 'firing' from a crashed worker → terminal
			// 'failed' (never re-armed: a crash may be post-send, re-arming would
			// double-sign).
			stuck, rerr := w.store.ReapStuckFiring(ctx, time.Now().UTC().Add(-stuckFiringTimeout))
			if rerr != nil {
				w.logger.Warn("oracle monitor: reap stuck firing failed", "err", rerr)
				w.mErr("reap")
				continue
			}
			for _, id := range stuck {
				w.logger.Warn("oracle monitor: trigger reaped from stuck firing", "trigger", id)
			}
		}
	}
}

// inBand reports whether `price` satisfies the band [min,max] after applying a
// hysteresis margin that shrinks the band inward (so the monitor only fires when
// the price is clearly inside, not flapping at the edge). The margin is
// hystBps basis points of each edge value. If the margin would invert the band
// (hysteresis wider than the band), it falls back to the raw band.
//
// Stop-loss "fire below X" uses band [0, X]: the max edge moves down to
// X·(1-hyst). Take-profit "fire above Y" uses band [Y, BIG]: the min edge moves
// up to Y·(1+hyst).
func inBand(price, min, max int64, hystBps int) bool {
	if hystBps <= 0 {
		return price >= min && price <= max
	}
	// margin = value/10000 * hystBps (divide first to avoid int64 overflow on
	// large prices; precision loss is negligible at the 1e8 scale).
	effMin := min + (absI64(min)/10000)*int64(hystBps)
	effMax := max - (absI64(max)/10000)*int64(hystBps)
	if effMin > effMax {
		return price >= min && price <= max
	}
	return price >= effMin && price <= effMax
}

func absI64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
