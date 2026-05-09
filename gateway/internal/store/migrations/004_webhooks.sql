-- Webhook System (Sprint 2 — Andromeda Features Roadmap §4).
--
-- Endpoints register URLs to receive events with HMAC-SHA256 signed payloads.
-- Deliveries queue is consumed by a dispatcher worker with backoff retry and
-- a dead-letter terminal state after N attempts.

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id      uuid        NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    url             text        NOT NULL,
    secret          text        NOT NULL,
    events          text[]      NOT NULL DEFAULT '{}',
    active          boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_success_at timestamptz,
    last_failure_at timestamptz,
    failure_count   int         NOT NULL DEFAULT 0,
    CONSTRAINT webhook_endpoints_url_https CHECK (url LIKE 'https://%' OR url LIKE 'http://localhost%' OR url LIKE 'http://127.%')
);

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_api_key ON webhook_endpoints(api_key_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_active ON webhook_endpoints(api_key_id) WHERE active = true;

DO $$ BEGIN
    CREATE TYPE webhook_delivery_status AS ENUM (
        'pending', 'in_flight', 'delivered', 'failed', 'dead_letter'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                   uuid                     PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id          uuid                     NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type           text                     NOT NULL,
    event_id             uuid                     NOT NULL,
    payload              jsonb                    NOT NULL,
    status               webhook_delivery_status  NOT NULL DEFAULT 'pending',
    attempts             int                      NOT NULL DEFAULT 0,
    next_attempt_at      timestamptz              NOT NULL DEFAULT now(),
    last_response_status int,
    last_response_body   text,
    created_at           timestamptz              NOT NULL DEFAULT now(),
    delivered_at         timestamptz
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending
    ON webhook_deliveries(status, next_attempt_at)
    WHERE status IN ('pending', 'in_flight');
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
    ON webhook_deliveries(endpoint_id, created_at DESC);
