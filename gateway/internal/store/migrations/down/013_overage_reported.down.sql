ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_overage_reported_nonneg;

ALTER TABLE subscriptions
  DROP COLUMN IF EXISTS stripe_overage_item_id,
  DROP COLUMN IF EXISTS overage_last_reported_at,
  DROP COLUMN IF EXISTS overage_reported_tokens;
