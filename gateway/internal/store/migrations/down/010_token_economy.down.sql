-- Down migration for 010_token_economy.sql.
-- Drops every table, column and constraint added by the forward migration.

DROP TABLE IF EXISTS notification_thresholds;
DROP TABLE IF EXISTS admin_audit_log;
DROP TABLE IF EXISTS admin_users;
DROP TABLE IF EXISTS pricing_history;
DROP TABLE IF EXISTS gift_cards;
DROP TABLE IF EXISTS credits;

ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_overage_used_nonneg,
  DROP CONSTRAINT IF EXISTS subscriptions_billing_cycle;
ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_tokens_used;
ALTER TABLE subscriptions
  ADD  CONSTRAINT subscriptions_tokens_used
       CHECK (tokens_used >= 0 AND tokens_used <= tokens_limit);

ALTER TABLE subscriptions
  DROP COLUMN IF EXISTS stripe_subscription_id,
  DROP COLUMN IF EXISTS stripe_customer_id,
  DROP COLUMN IF EXISTS billing_cycle,
  DROP COLUMN IF EXISTS overage_cap_tokens,
  DROP COLUMN IF EXISTS overage_used_tokens,
  DROP COLUMN IF EXISTS overage_card_present,
  DROP COLUMN IF EXISTS overage_enabled,
  DROP COLUMN IF EXISTS tx_burst,
  DROP COLUMN IF EXISTS tx_rps,
  DROP COLUMN IF EXISTS read_burst,
  DROP COLUMN IF EXISTS read_rps;

ALTER TABLE plans
  DROP CONSTRAINT IF EXISTS plans_tx_rps_nonneg,
  DROP CONSTRAINT IF EXISTS plans_read_rps_nonneg;
ALTER TABLE plans
  DROP COLUMN IF EXISTS is_giftable,
  DROP COLUMN IF EXISTS overage_per_1k_cents,
  DROP COLUMN IF EXISTS annual_price_cents,
  DROP COLUMN IF EXISTS tx_burst,
  DROP COLUMN IF EXISTS tx_rps,
  DROP COLUMN IF EXISTS read_burst,
  DROP COLUMN IF EXISTS read_rps;
