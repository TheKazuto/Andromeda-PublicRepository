-- Account lockout for both `users` (regular customers) and `admin_users`
-- (operators). Failed-login throttling defends against credential stuffing
-- when the IP-bucket rate limit is bypassed (distributed sources).
--
-- The `users` table is owned by the gateway, but the backend already extends
-- it with extra columns (see 001_init_users_apikeys.sql). Same pattern here:
-- ADD COLUMN IF NOT EXISTS so the migration is idempotent and safe to run
-- regardless of which service applied previous migrations first.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
