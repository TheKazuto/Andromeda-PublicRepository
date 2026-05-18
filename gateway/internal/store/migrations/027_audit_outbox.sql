-- P1.4 of the robustness plan: audit signer outbox.
--
-- Today Recorder.Append signs ed25519 inline. With Vault Transit that's a
-- 5-50ms HTTPS round-trip blocking the hot path *while holding a Postgres
-- transaction* — slow Vault → starved pool → stalled gateway. Worse, every
-- per-tenant chain serialises through this critical section, so a single
-- noisy tenant can hold conns.
--
-- This migration prepares the schema for an outbox model: rows are inserted
-- with signature NULL by the hot path (just prev_hash + entry_hash + INSERT),
-- and a dedicated worker drains the queue serially per tenant via
-- FOR UPDATE SKIP LOCKED. Chain integrity is unaffected because the chain is
-- defined by prev_hash + entry_hash; the signature is an external proof
-- attached afterwards.
--
-- Rollout:
--   1. Apply this migration (signature becomes nullable; existing rows stay
--      signed).
--   2. Deploy gateway code that inserts NULL signature + runs the signer
--      worker. The worker drains the queue on boot, so old rows from the
--      previous deploy that somehow lacked a signature get backfilled.

ALTER TABLE audit_log
    ALTER COLUMN signature DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS pending_signed_at timestamptz NULL;

-- The original signature length CHECK ran with signature NOT NULL; loosen
-- to allow NULL (pending) but still enforce 64 bytes when present.
ALTER TABLE audit_log
    DROP CONSTRAINT IF EXISTS audit_log_signature_len;
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_signature_len
        CHECK (signature IS NULL OR octet_length(signature) = 64);

-- Partial index — the worker queries only rows still pending.
CREATE INDEX IF NOT EXISTS idx_audit_log_pending
    ON audit_log (api_key_id, seq)
    WHERE signature IS NULL;
