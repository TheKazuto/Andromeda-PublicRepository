-- F7.5 — Pyth oracle price-trigger monitor (managed keeper).
--
-- A dev arms a price trigger: a pre-built `request_signature` payload plus the
-- price band that must hold for it to fire. A leader-elected worker
-- (gateway/internal/oraclemonitor) reads the live Pyth price off-chain from
-- Hermes (free) and, when the band is satisfied, fires the gas-sponsored
-- `request_signature` (with refresh-on-sign embedded). The on-chain KIND_ORACLE
-- dispatch re-validates the real price, so a wrong/compromised monitor cannot
-- forge a signature — it can only release a pre-committed message when the
-- on-chain rule would already pass. Single-shot (fires once, then terminal).
--
-- The band [min_1e8, max_1e8] mirrors the on-chain rule's band (canonical
-- decimal-1e8). The monitor fires when the live price is within the band; the
-- on-chain rule is the authority. Hysteresis keeps the monitor from flapping
-- at the band edge and wasting gas on txs that would revert.

DO $$ BEGIN
    CREATE TYPE oracle_price_trigger_status AS ENUM (
        'armed',
        'firing',
        'fired',
        'expired',
        'cancelled',
        'failed'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS oracle_price_triggers (
    id                        uuid                          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id                uuid                          NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    cluster                   text                          NOT NULL,
    dwallet_address           text                          NOT NULL,
    -- The FeedCache PDA the monitor watches (and the on-chain rule reads).
    feed_cache_pda            text                          NOT NULL,
    -- 32-byte Pyth feed id, hex (no 0x) — used for the Hermes latest-price lookup.
    pyth_feed_id_hex          text                          NOT NULL,
    -- Price band in canonical decimal-1e8 (mirrors the on-chain rule band).
    min_1e8                   bigint                        NOT NULL,
    max_1e8                   bigint                        NOT NULL,
    -- Margin (in basis points of the threshold) the live price must clear past
    -- the band edge before the monitor fires. 0 = fire as soon as in band.
    hysteresis_bps            int                           NOT NULL DEFAULT 0,
    -- Pre-built `request_signature` submit payload the worker fires when the
    -- band is satisfied. Same shape as POST /v1/policy/request-signature/submit.
    -- The dev fixes the message digest + destination here at arm time; the
    -- gateway never invents what gets signed.
    request_signature_payload jsonb                         NOT NULL DEFAULT '{}'::jsonb,
    -- Fire/expire are fanned out via the tenant's registered webhooks
    -- (event types oracle_trigger.fired / oracle_trigger.expired) — there is no
    -- per-trigger callback URL, so no unguarded outbound URL surface here.
    status                    oracle_price_trigger_status   NOT NULL DEFAULT 'armed',
    created_at                timestamptz                   NOT NULL DEFAULT now(),
    expires_at                timestamptz                   NOT NULL,
    fired_at                  timestamptz,
    tx_signature              text,
    last_check_at             timestamptz,
    last_price_1e8            bigint,
    failure_count             int                           NOT NULL DEFAULT 0,
    last_error                text,
    CONSTRAINT oracle_price_band_ok CHECK (min_1e8 <= max_1e8)
);

-- Hot path: the worker scans armed, unexpired triggers per tick.
CREATE INDEX IF NOT EXISTS idx_oracle_price_triggers_armed
    ON oracle_price_triggers(cluster, status, expires_at)
    WHERE status = 'armed';

-- Tenant list view.
CREATE INDEX IF NOT EXISTS idx_oracle_price_triggers_api_key
    ON oracle_price_triggers(api_key_id, created_at DESC);
