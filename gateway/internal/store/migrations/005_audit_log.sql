-- Audit Log (Sprint 2 — Andromeda Features Roadmap §6).
--
-- Per-tenant hash chain. `prev_hash` of the first entry for an api_key_id is
-- 32 zero bytes. `entry_hash = SHA-256(prev_hash || canonical-json(record))`.
-- `signature` is ed25519 over `entry_hash` using the Andromeda audit key.
-- The signing key SHOULD be managed via KMS in production — see CLAUDE.md
-- §3.2 / §6.

CREATE TABLE IF NOT EXISTS audit_log (
    seq           bigserial   PRIMARY KEY,
    api_key_id    uuid        NOT NULL,
    ts            timestamptz NOT NULL DEFAULT now(),
    event_type    text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    actor         text        NOT NULL,
    payload       jsonb       NOT NULL,
    cu_consumed   int,
    prev_hash     bytea       NOT NULL,
    entry_hash    bytea       NOT NULL,
    signature     bytea       NOT NULL,
    CONSTRAINT audit_log_hash_len CHECK (octet_length(entry_hash) = 32 AND octet_length(prev_hash) = 32),
    CONSTRAINT audit_log_signature_len CHECK (octet_length(signature) = 64)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_api_key_seq ON audit_log(api_key_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_time ON audit_log(event_type, ts DESC);
