-- =============================================================================
-- Per-key IP allowlist.
--
-- Each entry is either a plain IP ("192.168.1.5") or a CIDR ("10.0.0.0/24").
-- Empty array = no restriction (default). The middleware validates the
-- caller's RealIP against this list before any other authorization step.
-- =============================================================================

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS ip_allowlist text[] NOT NULL DEFAULT '{}';

-- Soft index for keys that have any restrictions — speeds up admin views
-- that filter by "keys with restrictions".
CREATE INDEX IF NOT EXISTS idx_api_keys_with_ip_restriction
  ON api_keys(id) WHERE array_length(ip_allowlist, 1) > 0;
