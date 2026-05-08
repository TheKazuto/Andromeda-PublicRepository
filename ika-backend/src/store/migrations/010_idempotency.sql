-- Idempotency-Key support (defensive mirror of the gateway middleware).
-- Engines remain custody-free; this table just caches recent (key + body)
-- → (status + response) tuples to prevent duplicate side effects on retry.

CREATE TABLE IF NOT EXISTS ika_idempotency_keys (
    scope            TEXT        NOT NULL,
    api_key_id       TEXT        NOT NULL DEFAULT '',
    method_path      TEXT        NOT NULL,
    idem_key         TEXT        NOT NULL,
    request_hash     TEXT        NOT NULL,
    status_code      INTEGER     NOT NULL,
    response_body    BYTEA       NOT NULL,
    response_headers JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, api_key_id, method_path, idem_key)
);

CREATE INDEX IF NOT EXISTS idx_ika_idempotency_expires ON ika_idempotency_keys(expires_at);
