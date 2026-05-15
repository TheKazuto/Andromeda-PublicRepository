-- TOTP replay protection. pquerna/otp accepts the same 6-digit code
-- multiple times inside its 30-second window — fine for a one-shot
-- second factor, fatal if the code leaks (shoulder surfing, intercept,
-- error message reflection) because the attacker can replay it.
--
-- We persist the LAST accepted window (= floor(unix_time / period)) per
-- admin and reject any code whose window is <= mfa_last_window. The
-- column is nullable because existing rows have no prior window.

ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS mfa_last_window BIGINT;
