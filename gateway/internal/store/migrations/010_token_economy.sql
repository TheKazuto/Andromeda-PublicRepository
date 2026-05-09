-- =============================================================================
-- Token economy v2.
--
-- Adds the schema needed for:
--   * 2 rate-limit buckets (read / tx) per plan + per subscription
--   * Annual billing cycle with 2-months-free discount
--   * Overage opt-in (card-required, hard cap 2× plan)
--   * Credits (granted by Andromeda, expire in 30 days)
--   * Gift cards (purchased or promotional, 12-month expiry)
--   * Scheduled pricing changes (notify 30d, grandfather active subs)
--   * Admin users with role-based access + audit log
--   * Threshold notification idempotency
--
-- All changes are additive: existing columns and behaviours stay until
-- callers (pricer, middleware) are migrated to the new shape.
-- =============================================================================

-- ----- plans: rate buckets v2 + annual + overage -----
ALTER TABLE plans
  ADD COLUMN IF NOT EXISTS read_rps              int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS read_burst            int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tx_rps                int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tx_burst              int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS annual_price_cents    int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS overage_per_1k_cents  int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS is_giftable           boolean NOT NULL DEFAULT false;

ALTER TABLE plans
  DROP CONSTRAINT IF EXISTS plans_read_rps_nonneg;
ALTER TABLE plans
  ADD  CONSTRAINT plans_read_rps_nonneg CHECK (read_rps >= 0 AND read_burst >= 0);
ALTER TABLE plans
  DROP CONSTRAINT IF EXISTS plans_tx_rps_nonneg;
ALTER TABLE plans
  ADD  CONSTRAINT plans_tx_rps_nonneg   CHECK (tx_rps   >= 0 AND tx_burst   >= 0);

-- ----- subscriptions: rate buckets v2 + overage + billing cycle + Stripe ids -----
ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS read_rps               int    NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS read_burst             int    NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tx_rps                 int    NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tx_burst               int    NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS overage_enabled        boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS overage_card_present   boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS overage_used_tokens    bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS overage_cap_tokens     bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS billing_cycle          text   NOT NULL DEFAULT 'monthly',
  ADD COLUMN IF NOT EXISTS stripe_customer_id     text,
  ADD COLUMN IF NOT EXISTS stripe_subscription_id text;

ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_billing_cycle;
ALTER TABLE subscriptions
  ADD  CONSTRAINT subscriptions_billing_cycle CHECK (billing_cycle IN ('monthly','annual'));

-- Old constraint forbade tokens_used > tokens_limit. Overage now allows
-- crossing the line under controlled conditions (card present + opt-in).
ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_tokens_used;
ALTER TABLE subscriptions
  ADD  CONSTRAINT subscriptions_tokens_used CHECK (tokens_used >= 0);

ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_overage_used_nonneg;
ALTER TABLE subscriptions
  ADD  CONSTRAINT subscriptions_overage_used_nonneg CHECK (overage_used_tokens >= 0);

-- ----- credits: tokens granted by Andromeda (trial / support / promo) -----
-- All credits expire in 30 days from grant. Consumed first in the token
-- consumption order (credits → monthly → gift_cards → overage).
CREATE TABLE IF NOT EXISTS credits (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount       bigint NOT NULL CHECK (amount > 0),
  consumed     bigint NOT NULL DEFAULT 0,
  reason       text   NOT NULL,
  granted_by   text   NOT NULL,
  expires_at   timestamptz NOT NULL,
  exhausted_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credits_consumed_lte_amount CHECK (consumed <= amount),
  CONSTRAINT credits_reason CHECK (reason IN ('trial','support','promo','hackathon','partner'))
);
CREATE INDEX IF NOT EXISTS idx_credits_user_active
  ON credits(user_id, expires_at)
  WHERE exhausted_at IS NULL;

-- ----- gift_cards: purchased (paid) or promotional (free) -----
-- redeem_token is the public-facing identifier embedded in the link the
-- buyer shares with the recipient. Format: 'gft_<base62-256bit-rand>'.
CREATE TABLE IF NOT EXISTS gift_cards (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  redeem_token      text NOT NULL UNIQUE,
  plan_code         text NOT NULL REFERENCES plans(code),
  duration_months   int  NOT NULL CHECK (duration_months IN (1, 12)),
  source            text NOT NULL,

  -- paid only
  buyer_user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
  buyer_email       text,
  paid_amount_cents int,
  stripe_payment_id text,

  -- promo only
  granted_by        text,

  message           text NOT NULL DEFAULT '',
  expires_at        timestamptz NOT NULL,
  redeemed_at       timestamptz,
  redeemed_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  refunded_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT gift_cards_source CHECK (source IN ('paid','promo')),
  CONSTRAINT gift_cards_paid_has_buyer CHECK (
    source <> 'paid' OR (paid_amount_cents IS NOT NULL AND paid_amount_cents > 0)
  ),
  CONSTRAINT gift_cards_promo_has_grantor CHECK (
    source <> 'promo' OR (granted_by IS NOT NULL AND granted_by <> '')
  ),
  CONSTRAINT gift_cards_not_redeemed_and_refunded CHECK (
    redeemed_at IS NULL OR refunded_at IS NULL
  )
);
CREATE INDEX IF NOT EXISTS idx_gift_cards_buyer        ON gift_cards(buyer_user_id);
CREATE INDEX IF NOT EXISTS idx_gift_cards_redeemed_by  ON gift_cards(redeemed_by);
CREATE INDEX IF NOT EXISTS idx_gift_cards_active
  ON gift_cards(redeem_token)
  WHERE redeemed_at IS NULL AND refunded_at IS NULL;

-- ----- pricing_history: scheduled, grandfathered changes -----
-- Created with effective_at in the future (≥ 30d). When effective_at is
-- reached, the apply worker copies new_value into the live table (plans
-- or request_costs) and stamps applied_at.
--
-- change_type drives the target table:
--   plan_price          → plans.price_cents
--   plan_annual_price   → plans.annual_price_cents
--   plan_tokens         → plans.monthly_tokens
--   plan_read_rps       → plans.read_rps
--   plan_tx_rps         → plans.tx_rps
--   plan_overage        → plans.overage_per_1k_cents
--   route_cost          → request_costs.cost_tokens
CREATE TABLE IF NOT EXISTS pricing_history (
  id                   bigserial PRIMARY KEY,
  change_type          text   NOT NULL,
  target_key           text   NOT NULL,
  old_value            bigint,
  new_value            bigint NOT NULL,
  effective_at         timestamptz NOT NULL,
  applied_at           timestamptz,
  cancelled_at         timestamptz,
  notification_sent_at timestamptz,
  created_by           text   NOT NULL,
  reason               text   NOT NULL DEFAULT '',
  created_at           timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pricing_history_change_type CHECK (
    change_type IN (
      'plan_price','plan_annual_price','plan_tokens',
      'plan_read_rps','plan_tx_rps','plan_overage',
      'route_cost'
    )
  ),
  CONSTRAINT pricing_history_one_terminal CHECK (
    applied_at IS NULL OR cancelled_at IS NULL
  )
);
CREATE INDEX IF NOT EXISTS idx_pricing_history_pending
  ON pricing_history(effective_at)
  WHERE applied_at IS NULL AND cancelled_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_pricing_history_target
  ON pricing_history(change_type, target_key, effective_at DESC);

-- ----- admin_users: separate auth namespace from regular users -----
CREATE TABLE IF NOT EXISTS admin_users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text NOT NULL UNIQUE,
  hashed_password text NOT NULL,
  role            text NOT NULL,
  mfa_secret      text,
  mfa_required    boolean NOT NULL DEFAULT false,
  is_active       boolean NOT NULL DEFAULT true,
  last_login_at   timestamptz,
  last_login_ip   text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT admin_users_role CHECK (role IN ('super_admin','support','billing'))
);

-- ----- admin_audit_log: every admin mutation lands here -----
-- Independent from the customer-facing audit_log table to keep concerns
-- separate (different consumers, different retention).
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id          bigserial PRIMARY KEY,
  admin_id    uuid NOT NULL REFERENCES admin_users(id) ON DELETE RESTRICT,
  admin_email text NOT NULL,
  action      text NOT NULL,
  target      text,
  payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_address  text,
  user_agent  text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_admin
  ON admin_audit_log(admin_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_action
  ON admin_audit_log(action, created_at DESC);

-- ----- notification_thresholds: idempotency for quota threshold alerts -----
-- One row per (subscription, period_start, threshold_pct). Insert with
-- ON CONFLICT DO NOTHING means the alert was already sent — skip the email
-- and webhook side effects.
CREATE TABLE IF NOT EXISTS notification_thresholds (
  id              bigserial PRIMARY KEY,
  subscription_id uuid NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  period_start    timestamptz NOT NULL,
  threshold_pct   int NOT NULL,
  notified_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT notification_thresholds_pct CHECK (threshold_pct IN (80, 95, 100, 200)),
  UNIQUE (subscription_id, period_start, threshold_pct)
);
CREATE INDEX IF NOT EXISTS idx_notification_thresholds_subscription
  ON notification_thresholds(subscription_id, period_start);
