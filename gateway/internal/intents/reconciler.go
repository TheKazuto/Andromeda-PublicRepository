package intents

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// Reconciler resolves intents stuck in non-final states: it expires stale
// PREPARED quotes, fails mid-flow intents that never broadcast, and polls the
// aggregator for the on-chain outcome of broadcast/unknown swaps. It never
// blind-retries a broadcast — it only reads status.
type Reconciler struct {
	store    intentStore
	up       *upstream.Registry
	metrics  *Metrics
	webhooks Publisher
	logger   *slog.Logger
	interval time.Duration
	// staleAfter is how long an intent may sit in a non-final, non-broadcast
	// state before the reconciler acts on it.
	staleAfter time.Duration
}

func NewReconciler(store intentStore, up *upstream.Registry, metrics *Metrics, webhooks Publisher, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		store:      store,
		up:         up,
		metrics:    metrics,
		webhooks:   webhooks,
		logger:     logger,
		interval:   30 * time.Second,
		staleAfter: 2 * time.Minute,
	}
}

// Run loops until ctx is cancelled. Intended to run leader-elected so a single
// replica reconciles.
func (rc *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(rc.interval)
	defer t.Stop()
	rc.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rc.sweep(ctx)
		}
	}
}

func (rc *Reconciler) sweep(ctx context.Context) {
	// Sample the oldest-open-age gauge per status (observability).
	if ages, err := rc.store.OldestOpenAgeByStatus(ctx); err == nil {
		rc.metrics.setOpenAges(ages)
	}

	open, err := rc.store.ListOpenOlderThan(ctx, rc.staleAfter, 100)
	if err != nil {
		rc.logger.Warn("intents reconciler list failed", "err", err)
		return
	}
	now := time.Now()
	for _, it := range open {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rc.resolve(ctx, it, now)
	}
}

func (rc *Reconciler) resolve(ctx context.Context, it *Intent, now time.Time) {
	switch it.Status {
	case StatusPrepared:
		if now.After(it.ExpiresAt) {
			_ = rc.store.SetStatus(ctx, it.ID, StatusExpired)
			rc.metrics.recordReconciler("expire", "ok")
		}
	case StatusAuthorizing, StatusSigning:
		// Crashed before any broadcast — no swap tx exists, safe to fail.
		_ = rc.store.SetError(ctx, it.ID, StatusFailed, "interrupted before broadcast")
		rc.metrics.recordReconciler("fail", "ok")
	case StatusApproving:
		// ERC20 approve broadcast; the swap leg needs the client to re-submit
		// (it carries the passphrase). Garbage-collect abandoned ones: if the
		// approve reverted on-chain, or it has been stuck well past the quote's
		// usefulness, fail it. (A confirmed approve leaves the allowance set, so a
		// fresh intent skips the approve — failing here is safe.)
		if it.ApproveTxHash != "" {
			if found, success := rc.receipt(ctx, it); found && !success {
				_ = rc.store.SetError(ctx, it.ID, StatusFailed, "ERC20 approval reverted on-chain")
				rc.metrics.recordReconciler("fail", "ok")
				return
			}
		}
		if now.Sub(it.UpdatedAt) > 10*time.Minute {
			_ = rc.store.SetError(ctx, it.ID, StatusFailed, "approval step not completed in time")
			rc.metrics.recordReconciler("fail", "ok")
		}
	case StatusBroadcasting:
		// We may or may not have broadcast — treat as unknown, then poll below.
		_ = rc.store.SaveBroadcast(ctx, it.ID, StatusBroadcastUnknown, it.SwapTxHash)
	case StatusSubmitted, StatusBroadcastUnknown, StatusSubmittedUnknown:
		rc.poll(ctx, it)
	}
}

// receipt checks the EVM approve tx receipt via the intents-backend.
func (rc *Reconciler) receipt(ctx context.Context, it *Intent) (bool, bool) {
	q := url.Values{}
	q.Set("chainId", it.ChainID)
	q.Set("txHash", it.ApproveTxHash)
	res, err := rc.up.Intents.Call(ctx, http.MethodGet, "/evm/receipt", q, nil, map[string]string{"X-Andromeda-User-Id": it.UserID})
	if err != nil || res.StatusCode != http.StatusOK {
		return false, false
	}
	var rcpt struct {
		Found   bool `json:"found"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(res.Body, &rcpt); err != nil {
		return false, false
	}
	return rcpt.Found, rcpt.Success
}

// poll asks the aggregator for the on-chain outcome of a broadcast swap.
func (rc *Reconciler) poll(ctx context.Context, it *Intent) {
	if it.SwapTxHash == "" {
		return // nothing to look up yet
	}
	q := url.Values{}
	q.Set("txHash", it.SwapTxHash)
	q.Set("fromChain", it.FromChain)
	q.Set("toChain", it.ToChain)
	res, err := rc.up.Intents.Call(ctx, http.MethodGet, "/tx-status", q, nil, nil)
	if err != nil || res.StatusCode != http.StatusOK {
		return // transient — try again next sweep
	}
	var st struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(res.Body, &st); err != nil {
		return
	}
	switch st.Status {
	case "DONE":
		_ = rc.store.SetStatus(ctx, it.ID, StatusSettled)
		rc.metrics.recordReconciler("settle", "ok")
		it.Status = StatusSettled
		rc.publish(ctx, it, "intent.swap.settled")
	case "FAILED":
		_ = rc.store.SetError(ctx, it.ID, StatusFailed, "swap failed on-chain")
		rc.metrics.recordReconciler("fail", "ok")
		it.Status = StatusFailed
		rc.publish(ctx, it, "intent.swap.failed")
	}
}

// publish emits a per-tenant webhook (best-effort, nil-safe).
func (rc *Reconciler) publish(ctx context.Context, it *Intent, event string) {
	if rc.webhooks == nil || it.APIKeyID == "" {
		return
	}
	apiKeyUUID, err := uuid.Parse(it.APIKeyID)
	if err != nil {
		return
	}
	_, _ = rc.webhooks.Publish(ctx, apiKeyUUID, event, map[string]any{
		"intentId":  it.ID,
		"status":    it.Status,
		"chainKind": it.ChainKind,
		"txHash":    it.SwapTxHash,
	})
}
