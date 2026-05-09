package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Schema notes:
// All billing-related columns/tables (subscriptions, gift_cards,
// stripe_events, etc) are owned by the gateway's migrations. Backend
// reads/writes via SQL only. Adding new columns or tables means a new
// gateway migration; backend never CREATEs in this domain.

const subColumns = `
	sub.id, sub.user_id, sub.plan_id, p.code, sub.status, sub.billing_cycle,
	sub.current_period_start, sub.current_period_end,
	sub.tokens_used, sub.tokens_limit,
	sub.overage_enabled, sub.overage_card_present,
	sub.overage_used_tokens, sub.overage_cap_tokens,
	sub.overage_reported_tokens, sub.overage_last_reported_at,
	COALESCE(sub.stripe_customer_id, ''), COALESCE(sub.stripe_subscription_id, ''),
	COALESCE(sub.stripe_overage_item_id, ''),
	sub.created_at, sub.updated_at`

func scanSubscription(row pgx.Row, sub *Subscription) error {
	return row.Scan(
		&sub.ID, &sub.UserID, &sub.PlanID, &sub.PlanCode, &sub.Status, &sub.BillingCycle,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.TokensUsed, &sub.TokensLimit,
		&sub.OverageEnabled, &sub.OverageCardPresent,
		&sub.OverageUsedTokens, &sub.OverageCapTokens,
		&sub.OverageReportedTokens, &sub.OverageLastReportedAt,
		&sub.StripeCustomerID, &sub.StripeSubscriptionID,
		&sub.StripeOverageItemID,
		&sub.CreatedAt, &sub.UpdatedAt,
	)
}

const giftCardColumns = `
	id, redeem_token, plan_code, duration_months, source,
	buyer_user_id, COALESCE(buyer_email, ''), paid_amount_cents,
	COALESCE(stripe_payment_id, ''), COALESCE(granted_by, ''),
	message, expires_at, redeemed_at, redeemed_by, refunded_at, created_at`

func scanGiftCard(row pgx.Row, g *GiftCard) error {
	return row.Scan(
		&g.ID, &g.RedeemToken, &g.PlanCode, &g.DurationMonths, &g.Source,
		&g.BuyerUserID, &g.BuyerEmail, &g.PaidAmountCents,
		&g.StripePaymentID, &g.GrantedBy,
		&g.Message, &g.ExpiresAt, &g.RedeemedAt, &g.RedeemedBy, &g.RefundedAt, &g.CreatedAt,
	)
}

// ----- BillingStore implementations on PostgresStore -----

func (s *PostgresStore) SetUserStripeCustomerID(ctx context.Context, userID, stripeCustomerID string) error {
	if userID == "" || stripeCustomerID == "" {
		return errors.New("userID and stripeCustomerID required")
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE users
		SET stripe_customer_id = $2
		WHERE id = $1
		  AND (stripe_customer_id IS NULL OR stripe_customer_id = $2)`,
		userID, stripeCustomerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAlreadyExists
	}
	return nil
}

func (s *PostgresStore) GetUserByStripeCustomerID(ctx context.Context, stripeCustomerID string) (*User, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, email, name, password_hash, plan, created_at
		FROM users WHERE stripe_customer_id = $1`, stripeCustomerID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Plan, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// AssignPlan creates or replaces the active subscription for a user.
// Mirrors the gateway logic so values stay consistent across services.
//
// A pg_advisory_xact_lock keyed off user_id serializes concurrent calls for
// the same user — without it two simultaneous AssignPlan transactions can
// each see an active subscription and "cancel" it, then each insert a new
// one, leaving the user with two active subscriptions. Lock is held until
// commit/rollback, no manual unlock needed.
func (s *PostgresStore) AssignPlan(ctx context.Context, userID, planCode string) (*Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('subscription:' || $1))`, userID); err != nil {
		return nil, fmt.Errorf("acquire subscription lock: %w", err)
	}

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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE subscriptions SET status = 'cancelled', updated_at = now()
		WHERE user_id = $1 AND status = 'active'`, userID); err != nil {
		return nil, err
	}

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
		        now(), now() + INTERVAL '1 month',
		        0, $3,
		        false, false, 0, $4,
		        $5, $6,
		        $7, $8, $9, $10)
		RETURNING id`,
		userID, planID, monthlyTokens, overageCap,
		legacyRps, legacyBurst, readRps, readBurst, txRps, txBurst).
		Scan(&subID)
	if err != nil {
		return nil, err
	}

	row := tx.QueryRow(ctx, `
		SELECT `+subColumns+`
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

func (s *PostgresStore) GetActiveSubscription(ctx context.Context, userID string) (*Subscription, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+subColumns+`
		FROM subscriptions sub
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.user_id = $1 AND sub.status = 'active'
		LIMIT 1`, userID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &sub, nil
}

func (s *PostgresStore) GetSubscriptionByStripeID(ctx context.Context, stripeSubscriptionID string) (*Subscription, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+subColumns+`
		FROM subscriptions sub
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.stripe_subscription_id = $1
		LIMIT 1`, stripeSubscriptionID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &sub, nil
}

func (s *PostgresStore) SetSubscriptionStripeIDs(ctx context.Context, subscriptionID, stripeCustomerID, stripeSubscriptionID string) error {
	if subscriptionID == "" {
		return errors.New("subscriptionID required")
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET stripe_customer_id     = COALESCE(NULLIF($2, ''), stripe_customer_id),
		    stripe_subscription_id = COALESCE(NULLIF($3, ''), stripe_subscription_id),
		    updated_at             = now()
		WHERE id = $1`,
		subscriptionID, stripeCustomerID, stripeSubscriptionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) SetSubscriptionStatus(ctx context.Context, subscriptionID, status string) error {
	status = strings.TrimSpace(status)
	switch status {
	case "active", "past_due", "cancelled", "trialing":
	default:
		return fmt.Errorf("status must be active|past_due|cancelled|trialing, got %q", status)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET status = $2, updated_at = now()
		WHERE id = $1`, subscriptionID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) UpdateSubscription(ctx context.Context, subscriptionID string, mut SubscriptionMutation) (*Subscription, error) {
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
		row := s.pool.QueryRow(ctx, `
			SELECT `+subColumns+`
			FROM subscriptions sub
			JOIN plans p ON p.id = sub.plan_id
			WHERE sub.id = $1`, subscriptionID)
		var sub Subscription
		if err := scanSubscription(row, &sub); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		return &sub, nil
	}
	sets = append(sets, "updated_at = now()")

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row first so two concurrent overage toggles or cap edits
	// observe a consistent before-state (otherwise a "last write wins"
	// race can swap an enabled overage back off, etc.).
	var lockedID string
	if err := tx.QueryRow(ctx, `SELECT id FROM subscriptions WHERE id = $1 FOR UPDATE`, subscriptionID).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock subscription: %w", err)
	}

	q := fmt.Sprintf(`UPDATE subscriptions SET %s WHERE id = $1`, strings.Join(sets, ", "))
	tag, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	row := tx.QueryRow(ctx, `
		SELECT `+subColumns+`
		FROM subscriptions sub
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.id = $1`, subscriptionID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (s *PostgresStore) SetSubscriptionOverageItem(ctx context.Context, subscriptionID, stripeItemID string) error {
	if subscriptionID == "" {
		return errors.New("subscriptionID required")
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET stripe_overage_item_id = NULLIF($2, ''),
		    updated_at             = now()
		WHERE id = $1`, subscriptionID, stripeItemID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) AdvanceOverageReported(ctx context.Context, subscriptionID string, delta int64) error {
	if delta <= 0 {
		return nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET overage_reported_tokens   = overage_reported_tokens + $2,
		    overage_last_reported_at  = now(),
		    updated_at                = now()
		WHERE id = $1`, subscriptionID, delta)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ListSubscriptionsForOverageReport(ctx context.Context) ([]OverageReportTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,
		       COALESCE(stripe_customer_id, ''),
		       COALESCE(stripe_subscription_id, ''),
		       COALESCE(stripe_overage_item_id, ''),
		       overage_used_tokens,
		       overage_reported_tokens
		FROM subscriptions
		WHERE status = 'active'
		  AND overage_enabled = true
		  AND stripe_subscription_id IS NOT NULL
		  AND overage_used_tokens > overage_reported_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OverageReportTarget{}
	for rows.Next() {
		var t OverageReportTarget
		if err := rows.Scan(&t.SubscriptionID,
			&t.StripeCustomerID, &t.StripeSubscriptionID,
			&t.StripeOverageItemID,
			&t.OverageUsedTokens, &t.OverageReportedTokens); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateGiftCard(ctx context.Context, in GiftCardCreate) (*GiftCard, error) {
	if in.RedeemToken == "" {
		return nil, errors.New("redeem_token required")
	}
	if in.PlanCode == "" {
		return nil, errors.New("plan_code required")
	}
	if in.DurationMonths != 1 && in.DurationMonths != 12 {
		return nil, errors.New("duration_months must be 1 or 12")
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO gift_cards
		    (redeem_token, plan_code, duration_months, source,
		     buyer_user_id, buyer_email, paid_amount_cents, stripe_payment_id,
		     granted_by, message, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING `+giftCardColumns,
		in.RedeemToken, in.PlanCode, in.DurationMonths, in.Source,
		in.BuyerUserID, nullableStr(in.BuyerEmail), in.PaidAmountCents, nullableStr(in.StripePaymentID),
		nullableStr(in.GrantedBy), in.Message, in.ExpiresAt)

	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return &g, nil
}

func (s *PostgresStore) MarkStripeEventProcessed(ctx context.Context, eventID, eventType, apiVersion string) (bool, error) {
	if eventID == "" {
		return false, errors.New("eventID required")
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO stripe_events (id, type, api_version)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (id) DO NOTHING`,
		eventID, eventType, apiVersion)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) UnmarkStripeEventProcessed(ctx context.Context, eventID string) error {
	if eventID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM stripe_events WHERE id = $1`, eventID)
	return err
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
