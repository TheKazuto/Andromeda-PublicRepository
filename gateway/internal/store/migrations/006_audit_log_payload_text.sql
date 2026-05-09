-- audit_log.payload was JSONB, but JSONB normalizes key ordering (by length,
-- then alphabetical), which corrupts the canonical JSON used to compute
-- entry_hash. Switch to TEXT to preserve the exact bytes that were hashed.
--
-- The audit table is empty in production at this point (only the seed
-- entries from the dev environment) — re-create cleanly.

DROP TABLE IF EXISTS audit_log;

CREATE TABLE audit_log (
    seq           bigserial   PRIMARY KEY,
    api_key_id    uuid        NOT NULL,
    ts            timestamptz NOT NULL DEFAULT now(),
    event_type    text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    actor         text        NOT NULL,
    payload       text        NOT NULL,
    cu_consumed   int,
    prev_hash     bytea       NOT NULL,
    entry_hash    bytea       NOT NULL,
    signature     bytea       NOT NULL,
    CONSTRAINT audit_log_hash_len CHECK (octet_length(entry_hash) = 32 AND octet_length(prev_hash) = 32),
    CONSTRAINT audit_log_signature_len CHECK (octet_length(signature) = 64)
);

CREATE INDEX idx_audit_log_api_key_seq ON audit_log(api_key_id, seq);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_event_time ON audit_log(event_type, ts DESC);
