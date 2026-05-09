package store

import (
	"context"
	"strings"
)

// SetUserStripeCustomerID associates a stripe_customer_id with a user.
// Idempotent: writing the same id is a no-op.
func (s *pgStore) SetUserStripeCustomerID(ctx context.Context, userID, stripeCustomerID string) error {
	if userID == "" || stripeCustomerID == "" {
		return errInvalid("userID and stripeCustomerID required")
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
		// Either user not found OR they already have a different customer.
		// We don't overwrite to avoid clobbering a hand-fixed mapping.
		return ErrAlreadyExists
	}
	return nil
}

func (s *pgStore) GetUserByStripeCustomerID(ctx context.Context, stripeCustomerID string) (*User, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT id, email, name, COALESCE(stripe_customer_id, ''), created_at
        FROM users
        WHERE stripe_customer_id = $1`, stripeCustomerID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.StripeCustomerID, &u.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *pgStore) SetSubscriptionStripeIDs(ctx context.Context, subscriptionID, stripeCustomerID, stripeSubscriptionID string) error {
	if subscriptionID == "" {
		return errInvalid("subscriptionID required")
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

func (s *pgStore) SetSubscriptionStatus(ctx context.Context, subscriptionID, status string) error {
	status = strings.TrimSpace(status)
	switch status {
	case "active", "past_due", "cancelled", "trialing":
	default:
		return errInvalid("status must be 'active', 'past_due', 'cancelled' or 'trialing'")
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

func (s *pgStore) GetSubscriptionByStripeID(ctx context.Context, stripeSubscriptionID string) (*Subscription, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.stripe_subscription_id = $1
        LIMIT 1`, stripeSubscriptionID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, mapErr(err)
	}
	return &sub, nil
}

// MarkStripeEventProcessed inserts the event id; returns true on first
// observation, false on conflict (Stripe redelivery — skip).
func (s *pgStore) MarkStripeEventProcessed(ctx context.Context, eventID, eventType, apiVersion string) (bool, error) {
	if eventID == "" {
		return false, errInvalid("eventID required")
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

// SetSubscriptionOverageItem persists the Stripe subscription_item id of
// the overage line. Empty string clears the column when the user opts
// out of overage.
func (s *pgStore) SetSubscriptionOverageItem(ctx context.Context, subscriptionID, stripeItemID string) error {
	if subscriptionID == "" {
		return errInvalid("subscriptionID required")
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

// AdvanceOverageReported atomically increments overage_reported_tokens
// by `delta` and stamps overage_last_reported_at = now(). Called by the
// reporting worker after Stripe acknowledges the meter event.
func (s *pgStore) AdvanceOverageReported(ctx context.Context, subscriptionID string, delta int64) error {
	if subscriptionID == "" {
		return errInvalid("subscriptionID required")
	}
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

