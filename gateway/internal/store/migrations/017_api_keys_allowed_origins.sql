-- =============================================================================
-- Per-key Origin allowlist (browser CORS enforcement).
--
-- Each entry is an exact origin in the form `scheme://host[:port]` (e.g.
-- `https://app.example.com`). No wildcards. Empty array = no restriction
-- (browser requests with any Origin are accepted). The gateway middleware
-- compares the request's Origin header against this list after the API key
-- is authenticated.
--
-- Server-to-server calls (no Origin header) are unaffected — Origin checks
-- only apply when a browser is making the request.
-- =============================================================================

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS allowed_origins text[] NOT NULL DEFAULT '{}';

-- Soft index for admin views that filter by "keys with origin restrictions".
CREATE INDEX IF NOT EXISTS idx_api_keys_with_origin_restriction
  ON api_keys(id) WHERE array_length(allowed_origins, 1) > 0;
