-- Initial schema for the Andromeda gateway.
--
-- Tables `users` and `api_keys` are also intended to be the source of
-- truth for the product backend (`backend/`) once it migrates from the
-- in-memory store to Postgres. The gateway is the schema owner.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email       text NOT NULL UNIQUE,
    name        text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL,
    prefix        text NOT NULL,
    hashed_key    text NOT NULL UNIQUE,
    scopes        text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(hashed_key) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS plans (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code              text NOT NULL UNIQUE,
    name              text NOT NULL,
    monthly_tokens    bigint NOT NULL DEFAULT 0,
    rate_limit_rps    int    NOT NULL DEFAULT 0,
    rate_limit_burst  int    NOT NULL DEFAULT 0,
    price_cents       int    NOT NULL DEFAULT 0,
    features          jsonb  NOT NULL DEFAULT '{}'::jsonb,
    is_active         boolean NOT NULL DEFAULT true,
    sort_order        int    NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT plans_monthly_tokens_nonneg CHECK (monthly_tokens >= 0),
    CONSTRAINT plans_rate_limit_nonneg     CHECK (rate_limit_rps >= 0 AND rate_limit_burst >= 0)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id               uuid NOT NULL REFERENCES plans(id),
    status                text NOT NULL DEFAULT 'active',
    current_period_start  timestamptz NOT NULL DEFAULT now(),
    current_period_end    timestamptz NOT NULL,
    tokens_used           bigint NOT NULL DEFAULT 0,
    tokens_limit          bigint NOT NULL DEFAULT 0,
    rate_limit_rps        int    NOT NULL DEFAULT 0,
    rate_limit_burst      int    NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT subscriptions_status      CHECK (status IN ('active','cancelled','past_due','trialing')),
    CONSTRAINT subscriptions_period      CHECK (current_period_end > current_period_start),
    CONSTRAINT subscriptions_tokens_used CHECK (tokens_used >= 0 AND tokens_used <= tokens_limit)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_one_active
    ON subscriptions(user_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS request_costs (
    route_key    text PRIMARY KEY,
    cost_tokens  int  NOT NULL DEFAULT 1,
    description  text NOT NULL DEFAULT '',
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT request_costs_positive CHECK (cost_tokens > 0)
);

CREATE TABLE IF NOT EXISTS usage_events (
    id              bigserial PRIMARY KEY,
    user_id         uuid NOT NULL,
    api_key_id      uuid,
    subscription_id uuid,
    route_key       text NOT NULL,
    cost_tokens     int  NOT NULL,
    status_code     int  NOT NULL,
    latency_ms      int  NOT NULL DEFAULT 0,
    request_id      text,
    occurred_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_usage_events_user_time
    ON usage_events(user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_subscription_time
    ON usage_events(subscription_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_route_time
    ON usage_events(route_key, occurred_at DESC);
