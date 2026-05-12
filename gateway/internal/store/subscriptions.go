package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// subscriptions persistence: AssignPlan / GetActiveSubscription /
// UpdateSubscription. Split out of postgres.go (the subscriptionColumns const
// and scanSubscription helper stay there, shared with consume.go).

// AssignPlan creates or replaces the active subscription for a user. The
// new subscription is snapshotted with the plan's current values for
// tokens, RPS buckets and overage cap (= 2× monthly_tokens).
func (s *pgStore) AssignPlan(ctx context.Context, userID, planCode string) (*Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		planID                             string
		monthlyTokens                      int64
		legacyRps, legacyBurst             int
		readRps, readBurst, txRps, txBurst int
	)
	err = tx.QueryRow(ctx, `
        SELECT id, monthly_tokens,
               rate_limit_rps, rate_limit_burst,
               read_rps, read_burst, tx_rps, tx_burst
        FROM plans WHERE code = $1 AND is_active = true`, planCode).
		Scan(&planID, &monthlyTokens,
			&legacyRps, &legacyBurst,
			&readRps, &readBurst, &txRps, &txBurst)
	if err != nil {
		return nil, mapErr(err)
	}

	if _, err := tx.Exec(ctx, `
        UPDATE subscriptions SET status = 'cancelled', updated_at = now()
        WHERE user_id = $1 AND status = 'active'`, userID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	end := nextPeriodEnd(now)
	overageCap := monthlyTokens * 2

	var subID string
	err = tx.QueryRow(ctx, `
        INSERT INTO subscriptions
            (user_id, plan_id, status, billing_cycle,
             current_period_start, current_period_end,
             tokens_used, tokens_limit,
             overage_enabled, overage_card_present, overage_used_tokens, overage_cap_tokens,
             rate_limit_rps, rate_limit_burst,
             read_rps, read_burst, tx_rps, tx_burst)
        VALUES ($1, $2, 'active', 'monthly',
                $3, $4,
                0, $5,
                false, false, 0, $6,
                $7, $8,
                $9, $10, $11, $12)
        RETURNING id`,
		userID, planID, now, end, monthlyTokens, overageCap,
		legacyRps, legacyBurst, readRps, readBurst, txRps, txBurst).
		Scan(&subID)
	if err != nil {
		return nil, err
	}

	// Re-read with the canonical column set so the returned struct is
	// consistent with GetActiveSubscription / AuthenticateAPIKey.
	row := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (s *pgStore) GetActiveSubscription(ctx context.Context, userID string) (*Subscription, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.user_id = $1 AND sub.status = 'active'
        LIMIT 1`, userID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, mapErr(err)
	}
	return &sub, nil
}

func (s *pgStore) UpdateSubscription(ctx context.Context, subscriptionID string, mut SubscriptionMutation) (*Subscription, error) {
	sets := []string{}
	args := []any{subscriptionID}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if mut.OverageEnabled != nil {
		add("overage_enabled", *mut.OverageEnabled)
	}
	if mut.OverageCardPresent != nil {
		add("overage_card_present", *mut.OverageCardPresent)
	}
	if mut.OverageCapTokens != nil {
		add("overage_cap_tokens", *mut.OverageCapTokens)
	}
	if mut.BillingCycle != nil {
		add("billing_cycle", *mut.BillingCycle)
	}
	if mut.StripeCustomerID != nil {
		add("stripe_customer_id", *mut.StripeCustomerID)
	}
	if mut.StripeSubscriptionID != nil {
		add("stripe_subscription_id", *mut.StripeSubscriptionID)
	}
	if len(sets) == 0 {
		// Nothing to update — return current state.
		row := s.pool.QueryRow(ctx, `
            SELECT `+subscriptionColumns+`
            FROM subscriptions sub
            JOIN plans p ON p.id = sub.plan_id
            WHERE sub.id = $1`, subscriptionID)
		var sub Subscription
		if err := scanSubscription(row, &sub); err != nil {
			return nil, mapErr(err)
		}
		return &sub, nil
	}
	sets = append(sets, "updated_at = now()")

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := fmt.Sprintf(`UPDATE subscriptions SET %s WHERE id = $1`, strings.Join(sets, ", "))
	tag, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	row := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subscriptionID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &sub, nil
}
