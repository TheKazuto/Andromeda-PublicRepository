-- Passkey-PRF (D1 Opção A) — credentials, challenges, recovery bindings.
--
-- Operational tables for the passkey-primary session flow defined in
-- `PLAN_KEYSPRING_INTEGRATION_2026_05.md` §5.6 + decisões D3/D4/D5/D6/D12.
-- ika-backend is the sole owner (D4). The gateway never reads these tables
-- directly — it reverse-proxies to /v1/recovery/primary/passkey/* and reads
-- the on-chain `RulesPolicy` for authoritative state.
--
-- Why each table exists, in plain terms:
--
--   passkey_credentials   — one row per registered passkey on a dWallet.
--                           Stores only PUBLIC material: the credential's
--                           Secp256r1 pubkey (the same value that ends up in
--                           `policy.primary_slot[1..34]`), the salt strategy
--                           metadata (D3), backup-state hints, and the
--                           anti-clone sign counter (D11). NEVER the raw
--                           `credentialId` (D12) and NEVER the PRF secret.
--   passkey_challenges    — single-use challenges issued by *-init routes.
--                           Bound to a purpose ('register' / 'session_open'
--                           / 'sign'), a TTL, and consumed by *-complete /
--                           *-submit. Replay-protected via the on-chain
--                           policy nonce on the path that matters, but we
--                           store these so /init can return a stable nonce
--                           the user's UI can wait on without re-querying
--                           the chain.
--   recovery_bindings     — D5 invariant: never revoke the *last* active
--                           method. One row per (dwallet, scheme) — passkey,
--                           OIDC, quorum member, etc.
--
-- All `BYTEA` fields are raw bytes (never hex). All hashes are SHA-256 32
-- bytes unless noted.

-- ── passkey_credentials ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                    TEXT        PRIMARY KEY,                  -- app-generated UUID
    tenant_id             TEXT        NOT NULL,                     -- gateway tenant id (multi-tenant safety)
    dwallet_address       TEXT        NOT NULL,                     -- on-chain dWallet (= `RulesPolicy.dwallet`)
    -- D12: only the SHA-256 hash; the raw credentialId is NEVER stored.
    credential_id_hash    BYTEA       NOT NULL,                     -- sha256(credentialId), 32 bytes
    -- 33-byte compressed Secp256r1 pubkey. Same value as `primary_slot[1..34]`.
    credential_public_key BYTEA       NOT NULL,
    -- Optional encryption material derived from PRF (browser side) — public
    -- key only. NULL when the credential is registered solely for signing
    -- (no E2E payload encryption flow in v1).
    enc_pub_key           BYTEA,
    rp_id                 TEXT        NOT NULL,                     -- D2: 'andromedainfra.pro' in prod (immutable)
    origin                TEXT        NOT NULL,                     -- e.g. 'https://app.andromedainfra.pro'
    -- D3: per-credential salt strategy. salt_id is a UUID v4 (16 raw bytes);
    -- salt_hash = sha256(raw_salt). raw_salt itself is derived
    -- HKDF(server_secret, salt_id) at use time — NEVER persisted.
    salt_id               BYTEA       NOT NULL,
    salt_hash             BYTEA       NOT NULL,
    -- D11: WebAuthn sign counter. Some authenticators (iCloud Keychain,
    -- Samsung Pass) return 0 forever; rollback rule is applied at use time.
    sign_count            BIGINT      NOT NULL DEFAULT 0,
    -- WebAuthn `flags & BE` / `flags & BS` — informational only.
    backup_eligible       BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_state          BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Comma-separated `transports` from `getTransports()`, e.g. 'usb,hybrid,internal'.
    transports            TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    CONSTRAINT chk_passkey_credentials_credential_id_hash_len
        CHECK (octet_length(credential_id_hash) = 32),
    CONSTRAINT chk_passkey_credentials_pubkey_len
        CHECK (octet_length(credential_public_key) = 33),
    CONSTRAINT chk_passkey_credentials_salt_hash_len
        CHECK (octet_length(salt_hash) = 32)
);

-- Same `credentialId` can never be registered twice (WebAuthn spec invariant).
CREATE UNIQUE INDEX IF NOT EXISTS uq_passkey_credentials_credential_id_hash
    ON passkey_credentials (credential_id_hash);

-- Hot path: list passkeys per dWallet (active only) for the dashboard / revoke
-- guard. Partial index keeps revoked rows out of the path that matters most.
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_dwallet_active
    ON passkey_credentials (dwallet_address)
    WHERE revoked_at IS NULL;

-- Multi-tenant safety: every CRUD path filters by tenant_id.
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_tenant
    ON passkey_credentials (tenant_id);

-- D6: max 5 credentials per dWallet. Enforced in application logic against
-- this partial index (`SELECT count(*) … WHERE dwallet=$1 AND revoked_at IS
-- NULL` then reject at HTTP 409 `max_credentials_per_dwallet`). A pure SQL
-- trigger could enforce it too, but the count vs. the lifecycle of the row
-- can race in concurrent registers; the app guard uses SELECT FOR UPDATE on
-- a transaction.

-- ── passkey_challenges ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS passkey_challenges (
    id          TEXT        PRIMARY KEY,                          -- app-generated UUID, returned to the client
    tenant_id   TEXT        NOT NULL,
    purpose     TEXT        NOT NULL,                             -- 'register' | 'session_open' | 'sign'
    -- 32-byte canonical challenge bytes the user's authenticator will sign.
    -- For purpose='register' this is a server-issued nonce; for
    -- 'session_open'/'sign' it is the `passkey_session_open_challenge` /
    -- `passkey_primary_use_challenge` (hash of human-message + binding fields).
    challenge   BYTEA       NOT NULL,
    -- Optional pin to a credential / dwallet / api_key for replay-binding.
    dwallet_address TEXT,
    credential_id_hash BYTEA,
    api_key_id  TEXT,
    -- Free-form payload (e.g. eph_pk, notAfter, expectedSessionNonce, etc).
    -- Validated by the *-complete handler — we redact secrets at write time.
    metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,                                      -- NULL until consumed; single-use
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_passkey_challenges_challenge_len
        CHECK (octet_length(challenge) = 32),
    CONSTRAINT chk_passkey_challenges_purpose
        CHECK (purpose IN ('register', 'session_open', 'sign'))
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_dwallet
    ON passkey_challenges (dwallet_address)
    WHERE dwallet_address IS NOT NULL;

-- Cleanup path: nightly job deletes WHERE expires_at < NOW() - interval '1 day'.
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expiry
    ON passkey_challenges (expires_at);

-- ── recovery_bindings ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS recovery_bindings (
    id              TEXT        PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    dwallet_address TEXT        NOT NULL,
    -- 1-byte scheme tag mirroring contracts/auth: 0=Ed25519, 1=Secp256k1,
    -- 2=Secp256r1, 3=WebAuthn (passkey session), 4=OidcJwt, plus
    -- application-defined values 100+ for `quorum` (M-of-N) and 101+ for
    -- other off-chain recovery rails. The exact mapping lives in
    -- `src/recovery/bindings.ts` (TBD — Bloco 3 das rotas).
    scheme          SMALLINT    NOT NULL,
    -- Either a `credential_id_hash` (FK passkey_credentials), a wallet
    -- pubkey, an OIDC addr_seed, a quorum member set hash, etc.
    -- Schema-on-read: the routes know how to interpret per scheme.
    binding_ref     BYTEA       NOT NULL,
    -- 'active' | 'revoked' — D5 invariant: never revoke the LAST 'active' row
    -- per (dwallet_address); enforced in app logic in a single transaction.
    status          TEXT        NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT chk_recovery_bindings_status
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT chk_recovery_bindings_revoked_at
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- Hot path: count active bindings for the "last method" guard.
CREATE INDEX IF NOT EXISTS idx_recovery_bindings_dwallet_active
    ON recovery_bindings (dwallet_address)
    WHERE status = 'active';

-- A given binding can only exist once per dwallet+scheme (re-registering
-- the same passkey returns the existing row instead of duplicating).
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_bindings_dwallet_scheme_ref
    ON recovery_bindings (dwallet_address, scheme, binding_ref);
