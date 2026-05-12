// Package pricing maintains an in-memory cache of route_key -> cost_tokens
// loaded from the request_costs table, refreshed on a timer.
package pricing

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

type Pricer struct {
	store        store.Store
	defaultCost  int
	refreshEvery time.Duration
	logger       *slog.Logger

	mu    sync.RWMutex
	costs map[string]int
}

func New(s store.Store, defaultCost int, refresh time.Duration, logger *slog.Logger) *Pricer {
	if defaultCost < 1 {
		defaultCost = 1
	}
	if refresh <= 0 {
		refresh = 60 * time.Second
	}
	return &Pricer{
		store:        s,
		defaultCost:  defaultCost,
		refreshEvery: refresh,
		logger:       logger,
		costs:        map[string]int{},
	}
}

// Cost returns the cost in tokens for a given route key, falling back
// to the configured default when the key is not present in the cache.
func (p *Pricer) Cost(key string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c, ok := p.costs[key]; ok {
		return c
	}
	return p.defaultCost
}

// Refresh pulls the latest costs from the store. Safe to call manually
// (e.g. right after PATCH /admin/request-costs).
func (p *Pricer) Refresh(ctx context.Context) error {
	items, err := p.store.ListRequestCosts(ctx)
	if err != nil {
		return err
	}
	next := make(map[string]int, len(items))
	for _, it := range items {
		next[it.RouteKey] = it.CostTokens
	}
	p.mu.Lock()
	p.costs = next
	p.mu.Unlock()
	return nil
}

// Start blocks until ctx is cancelled, refreshing the cache periodically.
// Run in its own goroutine.
func (p *Pricer) Start(ctx context.Context) {
	if err := p.Refresh(ctx); err != nil {
		p.logger.Warn("pricing initial refresh failed", "err", err)
	}
	ticker := time.NewTicker(p.refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.Refresh(ctx); err != nil {
				p.logger.Warn("pricing refresh failed", "err", err)
			}
		}
	}
}
