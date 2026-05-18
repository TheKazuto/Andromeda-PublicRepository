-- P0.1: atomic cross-replica idempotency reservation.
--
-- Until now, ika_idempotency_keys only persisted *completed* responses:
-- two replicas receiving the same Idempotency-Key simultaneously would both
-- pass the lookup, both execute the mutation, and only the first INSERT on
-- finish would win (ON CONFLICT DO NOTHING). With gas-sponsored signing
-- this means duplicate Solana transactions / duplicate spend.
--
-- This migration adds a status field and a reservation timestamp so the
-- middleware can claim the key BEFORE running the mutation. The claim is
-- atomic via INSERT … ON CONFLICT DO UPDATE … WHERE expired.

ALTER TABLE ika_idempotency_keys
    ADD COLUMN IF NOT EXISTS status            TEXT        NOT NULL DEFAULT 'completed',
    ADD COLUMN IF NOT EXISTS reserved_at       TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS reservation_id    TEXT        NULL,
    ADD COLUMN IF NOT EXISTS reservation_until TIMESTAMPTZ NULL;

-- response_body / status_code / response_headers became nullable because a
-- row that is still `in_progress` does not have a final response yet.
-- Existing rows are migrated to `completed` by the default above, so the
-- non-null invariant for completed rows is preserved.
ALTER TABLE ika_idempotency_keys
    ALTER COLUMN status_code      DROP NOT NULL,
    ALTER COLUMN response_body    DROP NOT NULL,
    ALTER COLUMN response_headers DROP DEFAULT,
    ALTER COLUMN response_headers DROP NOT NULL;

-- Enforce status enum at the DB level — typos in the application code
-- would otherwise persist unnoticed and break replay logic.
ALTER TABLE ika_idempotency_keys
    DROP CONSTRAINT IF EXISTS ika_idempotency_keys_status_chk;
ALTER TABLE ika_idempotency_keys
    ADD  CONSTRAINT ika_idempotency_keys_status_chk
        CHECK (status IN ('in_progress', 'completed'));

-- Index to find stale reservations during cleanup: any in_progress row
-- whose reservation_until has passed is up for grabs.
CREATE INDEX IF NOT EXISTS idx_ika_idempotency_in_progress
    ON ika_idempotency_keys (status, reservation_until)
    WHERE status = 'in_progress';
