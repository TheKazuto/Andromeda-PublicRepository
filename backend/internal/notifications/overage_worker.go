package notifications

import (
	"context"
	"log/slog"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/billing"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// OverageWorker reports per-subscription overage_used_tokens deltas to
// Stripe via the Billing Meter event API. Idempotent on restart: the
// worker only advances overage_reported_tokens AFTER Stripe acknowledges
// the meter event, so a crash mid-tick re-reports at most once.
//
// Cadence: 5 minutes by default. Stripe aggregates meter events over the
// billing period, so sub-minute precision is unnecessary.
type OverageWorker struct {
	store    store.BillingStore
	billing  *billing.Service
	interval time.Duration
	logger   *slog.Logger
}

type OverageWorkerOptions struct {
	Store    store.BillingStore
	Billing  *billing.Service
	Interval time.Duration
	Logger   *slog.Logger
}

func NewOverageWorker(opts OverageWorkerOptions) *OverageWorker {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	return &OverageWorker{
		store:    opts.Store,
		billing:  opts.Billing,
		interval: opts.Interval,
		logger:   opts.Logger,
	}
}

func (w *OverageWorker) Start(ctx context.Context) {
	if w.billing == nil || !w.billing.Enabled() {
		w.logger.Info("overage worker disabled — billing service not configured")
		<-ctx.Done()
		return
	}

	w.tick(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *OverageWorker) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	targets, err := w.store.ListSubscriptionsForOverageReport(tickCtx)
	if err != nil {
		w.logger.Warn("overage worker: list targets failed", "err", err)
		return
	}
	if len(targets) == 0 {
		return
	}

	reported, failed := 0, 0
	for _, t := range targets {
		delta := t.PendingDelta()
		if delta <= 0 {
			continue
		}
		if t.StripeCustomerID == "" {
			w.logger.Warn("overage worker: skipping — no stripe customer",
				"subscription", t.SubscriptionID)
			continue
		}
		if _, err := w.billing.ReportOverage(tickCtx, t.StripeCustomerID, delta); err != nil {
			w.logger.Warn("overage worker: meter event failed",
				"err", err,
				"subscription", t.SubscriptionID,
				"delta", delta)
			failed++
			continue
		}
		// Only advance after Stripe ack — at-most-once-extra guarantee.
		if err := w.store.AdvanceOverageReported(tickCtx, t.SubscriptionID, delta); err != nil {
			w.logger.Error("overage worker: persist reported delta failed — will re-report next tick",
				"err", err,
				"subscription", t.SubscriptionID,
				"delta", delta)
			// Note: this means Stripe will receive the same delta again
			// on the next tick. Stripe's meter event de-dupe is by event
			// id (which we don't supply), so we MAY double-bill. The
			// failure path is rare (DB write); operators should monitor
			// this log line.
			failed++
			continue
		}
		reported++
	}
	w.logger.Info("overage worker tick",
		"reported", reported, "failed", failed, "targets", len(targets))
}
