-- Aggregated email rate-limit buckets.
-- Replaces COUNT(*) over ika_identity_email_rate_log in the hot path.

CREATE TABLE IF NOT EXISTS ika_identity_email_rate_buckets (
  bucket_key TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (bucket_key, window_start)
);

CREATE INDEX IF NOT EXISTS ika_identity_email_rate_buckets_updated_idx
  ON ika_identity_email_rate_buckets(updated_at);
