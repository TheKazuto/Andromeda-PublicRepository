package notifications

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-backend/internal/store"
	"github.com/shinkalabs/andromeda-backend/internal/webhooks"
)

// PricingWorker fires email + webhook for pending pricing_history rows
// whose effective_at is within the next 30 days and have not yet had
// notifications dispatched (notification_sent_at IS NULL).
//
// Scope of v1:
//   - plan_*  → emails users with active subscription on the affected plan
//   - route_cost → SKIPPED in v1 (would email every active user; needs a
//     digest pipeline before we turn it on).
//
// Once a row has been processed, notification_sent_at is set so the next
// tick ignores it. Even if the worker crashes mid-loop, the next run
// picks up where it left off.
type PricingWorker struct {
	store        store.NotificationStore
	mailer       Mailer
	publisher    *webhooks.Publisher
	dashboardURL string
	fromAddr     string
	interval     time.Duration
	logger       *slog.Logger
}

type PricingWorkerOptions struct {
	Store        store.NotificationStore
	Mailer       Mailer
	Publisher    *webhooks.Publisher
	DashboardURL string
	FromAddr     string
	Interval     time.Duration
	Logger       *slog.Logger
}

func NewPricingWorker(opts PricingWorkerOptions) *PricingWorker {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	return &PricingWorker{
		store:        opts.Store,
		mailer:       opts.Mailer,
		publisher:    opts.Publisher,
		dashboardURL: opts.DashboardURL,
		fromAddr:     opts.FromAddr,
		interval:     opts.Interval,
		logger:       opts.Logger,
	}
}

func (w *PricingWorker) Start(ctx context.Context) {
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

func (w *PricingWorker) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pending, err := w.store.ListPendingPricingChanges(tickCtx)
	if err != nil {
		w.logger.Warn("pricing worker: list pending failed", "err", err)
		return
	}
	for _, c := range pending {
		if c.NotificationSentAt != nil {
			continue
		}
		if !strings.HasPrefix(c.ChangeType, "plan_") {
			// route_cost requires a digest pipeline; mark as notified so
			// the same row isn't reconsidered every tick.
			if err := w.store.MarkPricingChangeNotified(tickCtx, c.ID); err != nil {
				w.logger.Warn("pricing worker: skip-mark failed", "err", err, "id", c.ID)
			}
			continue
		}
		w.dispatchPlanChange(tickCtx, c)
	}
}

func (w *PricingWorker) dispatchPlanChange(ctx context.Context, c store.PricingChange) {
	planCode := c.TargetKey
	recipients, err := w.store.ListUsersOnPlan(ctx, planCode)
	if err != nil {
		w.logger.Warn("pricing worker: list users failed",
			"err", err, "plan", planCode, "id", c.ID)
		return
	}
	if len(recipients) == 0 {
		// Nobody on that plan today — still mark notified so we don't
		// retry forever.
		_ = w.store.MarkPricingChangeNotified(ctx, c.ID)
		return
	}

	subject := RenderPricingSubject(PricingTemplateInput{
		PlanCode:    planCode,
		EffectiveAt: c.EffectiveAt,
	})
	body := RenderPricingBody(PricingTemplateInput{
		PlanCode:     planCode,
		ChangeType:   c.ChangeType,
		OldValue:     c.OldValue,
		NewValue:     c.NewValue,
		EffectiveAt:  c.EffectiveAt,
		Reason:       c.Reason,
		DashboardURL: w.dashboardURL,
	})

	delivered := 0
	for _, r := range recipients {
		if err := w.mailer.Send(Message{
			From:      w.fromAddr,
			To:        r.UserEmail,
			Subject:   subject,
			PlainBody: body,
		}); err != nil {
			w.logger.Warn("pricing worker: email send failed",
				"err", err, "to", r.UserEmail, "id", c.ID)
		} else {
			delivered++
		}

		// Webhook fan-out via the user's primary API key, when present.
		if w.publisher == nil {
			continue
		}
		apiKey, err := w.store.GetPrimaryAPIKeyForUser(ctx, r.UserID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				w.logger.Warn("pricing worker: api key lookup failed",
					"err", err, "user", r.UserID)
			}
			continue
		}
		apiKeyUUID, err := uuid.Parse(apiKey.ID)
		if err != nil {
			w.logger.Warn("pricing worker: invalid api key uuid",
				"err", err, "user", r.UserID, "api_key_id", apiKey.ID)
			continue
		}
		payload := map[string]any{
			"changeId":    c.ID,
			"changeType":  c.ChangeType,
			"planCode":    planCode,
			"oldValue":    c.OldValue,
			"newValue":    c.NewValue,
			"effectiveAt": c.EffectiveAt,
			"reason":      c.Reason,
		}
		if _, err := w.publisher.Publish(ctx, apiKeyUUID, "pricing.changed", payload); err != nil {
			w.logger.Warn("pricing worker: webhook publish failed",
				"err", err, "user", r.UserID, "id", c.ID)
		}
	}

	if err := w.store.MarkPricingChangeNotified(ctx, c.ID); err != nil {
		w.logger.Warn("pricing worker: mark notified failed", "err", err, "id", c.ID)
		return
	}
	w.logger.Info("pricing worker: notifications fanned out",
		"plan", planCode, "delivered", delivered, "recipients", len(recipients), "id", c.ID)
}
