-- =============================================================================
-- Overage usage reporting state.
--
-- The reporting worker (notifications/overage_worker.go) consumes the
-- delta between overage_used_tokens and overage_reported_tokens, sends
-- it to Stripe as a meter event, then advances overage_reported_tokens.
-- Persisting the high-water mark on the subscription row makes the
-- worker safe to restart at any time without double-reporting.
--
-- We also remember the Stripe subscription_item id of the overage line
-- so the client knows which item to remove when the user opts out.
-- =============================================================================

ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS overage_reported_tokens   bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS overage_last_reported_at  timestamptz,
  ADD COLUMN IF NOT EXISTS stripe_overage_item_id    text;

ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_overage_reported_nonneg;
ALTER TABLE subscriptions
  ADD  CONSTRAINT subscriptions_overage_reported_nonneg
       CHECK (overage_reported_tokens >= 0);
