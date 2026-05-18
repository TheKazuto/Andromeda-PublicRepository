-- Track the audit_log snapshot progress for the daily R2/S3 dump worker.
--
-- The snapshotter reads from `last_seq + 1` up to the current head and
-- uploads a single NDJSON.gz to object storage. Object key includes the
-- date for cheap point-in-time lookup; we don't index it because the
-- file count grows by 1 per day.
--
-- We store one row per upload (not just the latest cursor) so an
-- operator can audit when each snapshot happened, how large it was,
-- and which bucket/key holds it.

CREATE TABLE IF NOT EXISTS audit_snapshot_log (
    id              bigserial    PRIMARY KEY,
    snapshot_date   date         NOT NULL,
    first_seq       bigint       NOT NULL,
    last_seq        bigint       NOT NULL,
    row_count       bigint       NOT NULL,
    byte_count      bigint       NOT NULL,
    object_key      text         NOT NULL,
    uploaded_at     timestamptz  NOT NULL DEFAULT NOW()
);

-- Lookup the latest cursor cheaply.
CREATE INDEX IF NOT EXISTS idx_audit_snapshot_log_uploaded_at
    ON audit_snapshot_log (uploaded_at DESC);

-- One snapshot per (date, last_seq) pair — defends against the worker
-- re-running on the same calendar day if a leader hand-off happens.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_snapshot_log_date_seq
    ON audit_snapshot_log (snapshot_date, last_seq);
