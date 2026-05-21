-- Pyth adapter — oracle feed registry + refresh log.
-- The leader-elected crank (gateway/internal/oraclerelay) keeps each feed's
-- on-chain FeedCache PDA fresh by copying a Pyth PriceUpdateV2 into the
-- canonical 64-byte view the policy-engine KIND_ORACLE dispatch reads.

CREATE TABLE IF NOT EXISTS oracle_feeds (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label               TEXT NOT NULL,                  -- "SOL/USD"
    cluster             TEXT NOT NULL,                  -- 'devnet' | 'mainnet'
    pyth_feed_id_hex    TEXT NOT NULL,                  -- 32-byte feed id, hex (no 0x)
    feed_cache_pda      TEXT NOT NULL,                  -- base58, [b"feed_cache", feed_id]
    pyth_account        TEXT NOT NULL,                  -- base58 PriceUpdateV2 source
    pyth_account_kind   TEXT NOT NULL DEFAULT 'price_feed'
        CHECK (pyth_account_kind IN ('price_feed', 'price_update_v2')),
    refresh_interval_s  INTEGER NOT NULL DEFAULT 30,
    paused              BOOLEAN NOT NULL DEFAULT FALSE,
    last_publish_time   TIMESTAMPTZ,
    last_tx_signature   TEXT,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cluster, pyth_feed_id_hex)
);

CREATE TABLE IF NOT EXISTS oracle_feed_refresh_log (
    id                BIGSERIAL PRIMARY KEY,
    feed_id           UUID NOT NULL REFERENCES oracle_feeds(id) ON DELETE CASCADE,
    refreshed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    tx_signature      TEXT,
    pyth_publish_time TIMESTAMPTZ,
    price_q64         BIGINT,    -- canonical decimal-1e8 price
    conf_q64          BIGINT,    -- canonical decimal-1e8 confidence
    result            TEXT NOT NULL DEFAULT 'success'
        CHECK (result IN ('success', 'skipped', 'stale', 'error')),
    error             TEXT
);

CREATE INDEX IF NOT EXISTS idx_refresh_log_feed_time
    ON oracle_feed_refresh_log (feed_id, refreshed_at DESC);

CREATE INDEX IF NOT EXISTS idx_oracle_feeds_active
    ON oracle_feeds (cluster, paused, refresh_interval_s);
