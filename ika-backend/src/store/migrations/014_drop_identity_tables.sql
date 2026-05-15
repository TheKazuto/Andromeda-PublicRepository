-- Migration 014 — drop the legacy Identity Layer tables.
--
-- The Identity Layer (`/v1/identity/*`, OAuth-as-mapping, email magic-link,
-- passkey-PRF, account linking) was retired in favor of Login Social (OIDC,
-- `scheme = 4`), which is the only path that lets a social identity be the
-- on-chain owner of a dWallet *and* sign transactions. The old Identity Layer
-- only mapped a wallet address from `sha256("provider:sub")` and could not own
-- or sign.
--
-- Devnet pre-alpha — no real funds; safe to drop in cascade.

DROP TABLE IF EXISTS ika_identity_audit                CASCADE;
DROP TABLE IF EXISTS ika_identity_refresh_tokens       CASCADE;
DROP TABLE IF EXISTS ika_identity_oauth_states         CASCADE;
DROP TABLE IF EXISTS ika_identity_email_tokens         CASCADE;
DROP TABLE IF EXISTS ika_identity_email_rate_buckets   CASCADE;
DROP TABLE IF EXISTS ika_identity_email_rate_log       CASCADE;
DROP TABLE IF EXISTS ika_identity_passkey_challenges   CASCADE;
DROP TABLE IF EXISTS ika_identity_passkeys             CASCADE;
DROP TABLE IF EXISTS ika_identity_links                CASCADE;
DROP TABLE IF EXISTS ika_identity_config               CASCADE;
DROP TABLE IF EXISTS ika_identities                    CASCADE;
