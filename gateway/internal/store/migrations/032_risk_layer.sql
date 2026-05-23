-- F-RISK-0 — Risk scoring layer foundation (config, blocklist, denylist, allowlist, history, feed runs).
-- This migration defines the schema for the off-chain risk evaluation gate that runs
-- in the gateway before signing. All tables are scoped to tenant/dWallet except the
-- global blocklist. Address normalization: lowercase hex (no 0x prefix).
--
-- `tenant_id` is the API key id (api_keys.id) as a string — the gateway's tenant
-- identity. It is stored as TEXT (not a uuid FK to api_keys) because the whole
-- risk code path treats the tenant id as a string; there is no `tenants` table.

-- Per-dWallet risk configuration (fallback per-tenant defaults available via FK to risk_tenant_defaults).
CREATE TABLE IF NOT EXISTS risk_config (
    dwallet_address       TEXT PRIMARY KEY,           -- normalized destination address (pk)
    tenant_id             TEXT NOT NULL,  -- api_keys.id as string (no FK: api_keys.id is uuid; tenant identity is the API key id)
    warn_level            TEXT NOT NULL DEFAULT 'high'
        CHECK (warn_level IN ('none', 'low', 'medium', 'high', 'critical')),
    block_level           TEXT NOT NULL DEFAULT 'critical'
        CHECK (block_level IN ('none', 'low', 'medium', 'high', 'critical')),
    simulation_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    fail_mode             TEXT NOT NULL DEFAULT 'open'
        CHECK (fail_mode IN ('open', 'closed')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_config_tenant
    ON risk_config (tenant_id);

-- Per-tenant default risk configuration (used as fallback for dWallets without explicit config).
CREATE TABLE IF NOT EXISTS risk_tenant_defaults (
    tenant_id             TEXT PRIMARY KEY,  -- api_keys.id as string (no FK: api_keys.id is uuid; tenant identity is the API key id)
    warn_level            TEXT NOT NULL DEFAULT 'high'
        CHECK (warn_level IN ('none', 'low', 'medium', 'high', 'critical')),
    block_level           TEXT NOT NULL DEFAULT 'critical'
        CHECK (block_level IN ('none', 'low', 'medium', 'high', 'critical')),
    simulation_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    fail_mode             TEXT NOT NULL DEFAULT 'open'
        CHECK (fail_mode IN ('open', 'closed')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant denylist: explicit destinations the tenant has marked as blocked.
CREATE TABLE IF NOT EXISTS risk_denylist (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,  -- api_keys.id as string (no FK: api_keys.id is uuid; tenant identity is the API key id)
    destination           TEXT NOT NULL,              -- normalized destination address
    reason                TEXT,                       -- optional user-provided reason
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, destination)
);

CREATE INDEX IF NOT EXISTS idx_risk_denylist_tenant
    ON risk_denylist (tenant_id);

-- Per-tenant allowlist: explicit destinations the tenant has whitelisted.
-- Used to override false positives from blocklist or heuristics.
CREATE TABLE IF NOT EXISTS risk_allowlist (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,  -- api_keys.id as string (no FK: api_keys.id is uuid; tenant identity is the API key id)
    destination           TEXT NOT NULL,              -- normalized destination address
    reason                TEXT,                       -- optional user-provided reason
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, destination)
);

CREATE INDEX IF NOT EXISTS idx_risk_allowlist_tenant
    ON risk_allowlist (tenant_id);

-- Global blocklist: ingested from external open-source feeds.
-- Addresses tracked here are flagged as high-risk.
CREATE TABLE IF NOT EXISTS risk_blocklist (
    destination           TEXT PRIMARY KEY,           -- normalized destination address (pk)
    source                TEXT NOT NULL,              -- feed source (e.g., "etherscan-phishing", "forta-drainer")
    category              TEXT NOT NULL,              -- category (e.g., "phishing", "drainer", "malware")
    license               TEXT,                       -- source license for audit trail
    fetched_at            TIMESTAMPTZ NOT NULL,       -- when this entry was last updated
    content_hash          TEXT,                       -- hash of the fetched feed for dedup
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_blocklist_source
    ON risk_blocklist (source);

-- Per-dWallet destination history: tracks addresses this dWallet has sent to.
-- Populated on successful submit; used to detect "first time to this address" signal.
CREATE TABLE IF NOT EXISTS dest_history (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dwallet_address       TEXT NOT NULL,              -- normalized dWallet address
    destination           TEXT NOT NULL,              -- normalized destination address
    first_used_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    count                 BIGINT NOT NULL DEFAULT 1, -- incremented on each submit
    UNIQUE (dwallet_address, destination)
);

CREATE INDEX IF NOT EXISTS idx_dest_history_dwallet
    ON dest_history (dwallet_address);

-- Risk feed ingestion state: tracks when each blocklist feed was last successfully fetched.
-- Used for dedup between replicas and to detect staleness.
CREATE TABLE IF NOT EXISTS risk_feed_runs (
    feed_url              TEXT PRIMARY KEY,           -- feed source URL (pk)
    last_success_at       TIMESTAMPTZ,                -- last successful fetch
    last_error_at         TIMESTAMPTZ,                -- last error
    last_error_msg        TEXT,                       -- error message
    entries_upserted      INTEGER NOT NULL DEFAULT 0, -- count of entries from this fetch
    content_hash          TEXT,                       -- hash of fetched content for dedup
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed request costs for new risk management routes.
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('gateway.risk.get-config', 1, 'Gateway: risk config read (T1)'),
    ('gateway.risk.put-config', 5, 'Gateway: risk config write (T1)'),
    ('gateway.risk.get-defaults', 1, 'Gateway: risk tenant defaults read (T1)'),
    ('gateway.risk.put-defaults', 5, 'Gateway: risk tenant defaults write (T1)'),
    ('gateway.risk.post-denylist', 5, 'Gateway: risk denylist add (T1)'),
    ('gateway.risk.delete-denylist', 5, 'Gateway: risk denylist remove (T1)'),
    ('gateway.risk.post-allowlist', 5, 'Gateway: risk allowlist add (T1)'),
    ('gateway.risk.delete-allowlist', 5, 'Gateway: risk allowlist remove (T1)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at = now();
