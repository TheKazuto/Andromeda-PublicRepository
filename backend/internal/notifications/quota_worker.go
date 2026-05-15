package notifications

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-backend/internal/store"
	"github.com/shinkalabs/andromeda-backend/internal/webhooks"
)

// QuotaWorker scans active subscriptions, computes the (used + overage)
// percentage relative to tokens_limit, and fires email + webhook the
// FIRST time each threshold (80, 95, 100, 200) is crossed in the current
// period. Idempotency is provided by the `notification_thresholds` table
// — see store.MarkThresholdNotified.
type QuotaWorker struct {
	store        store.NotificationStore
	mailer       Mailer
	publisher    *webhooks.Publisher
	dashboardURL string
	fromAddr     string
	interval     time.Duration
	logger       *slog.Logger
}

type QuotaWorkerOptions struct {
	Store        store.NotificationStore
	Mailer       Mailer
	Publisher    *webhooks.Publisher
	DashboardURL string
	FromAddr     string
	Interval     time.Duration
	Logger       *slog.Logger
}

func NewQuotaWorker(opts QuotaWorkerOptions) *QuotaWorker {
	if opts.Interval <= 0 {
		opts.Interval = 60 * time.Second
	}
	return &QuotaWorker{
		store:        opts.Store,
		mailer:       opts.Mailer,
		publisher:    opts.Publisher,
		dashboardURL: opts.DashboardURL,
		fromAddr:     opts.FromAddr,
		interval:     opts.Interval,
		logger:       opts.Logger,
	}
}

// Start blocks until ctx is cancelled. Run in its own goroutine.
func (w *QuotaWorker) Start(ctx context.Context) {
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

// allThresholds is the set checked on every tick, ascending. We fire the
// HIGHEST crossed threshold first so a burst that jumps from 70% → 100%
// in one go marks all three (80/95/100) as notified.
var allThresholds = []int{80, 95, 100, 200}

func (w *QuotaWorker) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	subs, err := w.store.ListActiveSubscriptionsForNotifications(tickCtx)
	if err != nil {
		w.logger.Warn("quota worker: list subscriptions failed", "err", err)
		return
	}
	for _, sub := range subs {
		w.processSubscription(tickCtx, sub)
	}
}

func (w *QuotaWorker) processSubscription(ctx context.Context, sub store.NotificationSubscription) {
	pct := sub.UsedPercent()
	if pct < 80 {
		return
	}

	for _, threshold := range allThresholds {
		if pct < threshold {
			continue
		}
		fired, err := w.store.MarkThresholdNotified(ctx, sub.SubscriptionID, sub.PeriodStart, threshold)
		if err != nil {
			w.logger.Warn("quota worker: mark notified failed",
				"err", err, "subscription", sub.SubscriptionID, "threshold", threshold)
			continue
		}
		if !fired {
			// Already notified this threshold this period — silence.
			continue
		}
		w.dispatch(ctx, sub, threshold)
	}
}

func (w *QuotaWorker) dispatch(ctx context.Context, sub store.NotificationSubscription, threshold int) {
	// 1. Email
	subject := RenderQuotaSubject(QuotaTemplateInput{
		PlanCode:     sub.PlanCode,
		ThresholdPct: threshold,
	})
	body := RenderQuotaBody(QuotaTemplateInput{
		Email:        sub.UserEmail,
		PlanCode:     sub.PlanCode,
		ThresholdPct: threshold,
		TokensUsed:   sub.TokensUsed,
		OverageUsed:  sub.OverageUsedTokens,
		TokensLimit:  sub.TokensLimit,
		PeriodEnd:    sub.PeriodEnd,
		DashboardURL: w.dashboardURL,
	})
	if err := w.mailer.Send(Message{
		From:      w.fromAddr,
		To:        sub.UserEmail,
		Subject:   subject,
		PlainBody: body,
	}); err != nil {
		w.logger.Warn("quota worker: email send failed",
			"err", err, "to", sub.UserEmail, "threshold", threshold)
	} else {
		w.logger.Info("quota worker: email sent",
			"to", sub.UserEmail, "threshold", threshold, "plan", sub.PlanCode)
	}

	// 2. Webhook (best-effort — picks the user's primary API key for fan-out)
	if w.publisher == nil {
		return
	}
	apiKey, err := w.store.GetPrimaryAPIKeyForUser(ctx, sub.UserID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			w.logger.Warn("quota worker: api key lookup failed",
				"err", err, "user", sub.UserID)
		}
		return
	}
	apiKeyUUID, err := uuid.Parse(apiKey.ID)
	if err != nil {
		w.logger.Warn("quota worker: invalid api key uuid",
			"err", err, "user", sub.UserID, "api_key_id", apiKey.ID)
		return
	}
	payload := map[string]any{
		"subscriptionId": sub.SubscriptionID,
		"planCode":       sub.PlanCode,
		"thresholdPct":   threshold,
		"tokensUsed":     sub.TokensUsed,
		"overageUsed":    sub.OverageUsedTokens,
		"tokensLimit":    sub.TokensLimit,
		"periodStart":    sub.PeriodStart,
		"periodEnd":      sub.PeriodEnd,
	}
	if _, err := w.publisher.Publish(ctx, apiKeyUUID, "usage.threshold_reached", payload); err != nil {
		w.logger.Warn("quota worker: webhook publish failed",
			"err", err, "user", sub.UserID, "threshold", threshold)
	}
}
