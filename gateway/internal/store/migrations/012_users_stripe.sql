-- =============================================================================
-- Stripe customer linkage on users.
--
-- One Stripe customer per Andromeda user, lazily created the first time a
-- user goes through checkout. Subscription rows continue to carry their
-- own stripe_subscription_id so we can track multiple historical subs
-- (cancelled, replaced, etc) under the same customer.
--
-- We also stamp a small dedupe table for Stripe webhook events so retries
-- by Stripe don't double-apply state.
-- =============================================================================

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS stripe_customer_id text;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_stripe_customer
  ON users(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

-- Webhook event dedupe. Stripe redeliveries carry the same event id; the
-- handler inserts here first and short-circuits on conflict. Rows older
-- than 30 days can be pruned by an offline job — no FK pressure.
CREATE TABLE IF NOT EXISTS stripe_events (
  id           text PRIMARY KEY,             -- Stripe event id, e.g. 'evt_...'
  type         text NOT NULL,
  api_version  text,
  received_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stripe_events_received
  ON stripe_events(received_at DESC);
