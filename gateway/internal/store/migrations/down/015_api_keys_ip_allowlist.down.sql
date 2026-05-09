DROP INDEX IF EXISTS idx_api_keys_with_ip_restriction;
ALTER TABLE api_keys DROP COLUMN IF EXISTS ip_allowlist;
