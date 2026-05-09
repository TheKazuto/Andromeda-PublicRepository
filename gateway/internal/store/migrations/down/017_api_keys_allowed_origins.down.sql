DROP INDEX IF EXISTS idx_api_keys_with_origin_restriction;
ALTER TABLE api_keys DROP COLUMN IF EXISTS allowed_origins;
