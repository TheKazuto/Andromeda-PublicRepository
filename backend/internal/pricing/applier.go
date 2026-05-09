// Package pricing in the backend hosts only the applier worker. The
// in-memory `Pricer` cache stays in the gateway (only the gateway
// reads request_costs on the hot path). When the applier writes new
// values to request_costs / plans, the gateway picks them up on its
// next 60s cache refresh — that lag is acceptable because pricing
// changes are scheduled with ≥30 days notice.
package pricing

import (
	"context"
	"log/slog"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// Applier periodically calls store.ApplyPendingPricingChanges, so that
// any pricing_history rows whose effective_at has arrived land in the
// live tables (request_costs / plans).
//
// Cadence: 60s. Pricing changes are scheduled with at least 30 days of
// notice; sub-minute precision is irrelevant.
type Applier struct {
	store    store.PricingStore
	interval time.Duration
	logger   *slog.Logger
}

// NewApplier wires the worker.
func NewApplier(s store.PricingStore, logger *slog.Logger) *Applier {
	return &Applier{
		store:    s,
		interval: 60 * time.Second,
		logger:   logger,
	}
}

// Start runs the applier loop. Blocks until ctx is cancelled.
func (a *Applier) Start(ctx context.Context) {
	a.tick(ctx)

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.tick(ctx)
		}
	}
}

func (a *Applier) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	results, err := a.store.ApplyPendingPricingChanges(tickCtx)
	if err != nil {
		a.logger.Warn("pricing applier tick failed", "err", err)
		return
	}
	if len(results) == 0 {
		return
	}

	var (
		applied int
		failed  int
	)
	for _, r := range results {
		if r.Error != nil {
			failed++
			a.logger.Error("pricing change apply failed",
				"id", r.ChangeID,
				"type", r.ChangeType,
				"target", r.TargetKey,
				"err", r.Error)
			continue
		}
		applied++
		a.logger.Info("pricing change applied",
			"id", r.ChangeID,
			"type", r.ChangeType,
			"target", r.TargetKey,
			"new_value", r.NewValue)
	}

	a.logger.Info("pricing applier tick",
		"applied", applied, "failed", failed, "total", len(results))
}
