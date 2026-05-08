-- ─────────────────────────────────────────────────────────────────
-- ika-backend — initial schema
-- Phase 0: bootstrap + identity + recovery
-- ─────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─── Identity Layer ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ika_identities (
  wallet_address TEXT PRIMARY KEY,
  primary_provider TEXT NOT NULL,
  primary_subject TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS ika_identities_provider_subject_idx
  ON ika_identities(primary_provider, primary_subject);

CREATE TABLE IF NOT EXISTS ika_identity_links (
  alias_provider TEXT NOT NULL,
  alias_subject TEXT NOT NULL,
  primary_wallet_address TEXT NOT NULL REFERENCES ika_identities(wallet_address) ON DELETE CASCADE,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (alias_provider, alias_subject)
);
CREATE INDEX IF NOT EXISTS ika_identity_links_wallet_idx
  ON ika_identity_links(primary_wallet_address);

CREATE TABLE IF NOT EXISTS ika_identity_passkeys (
  credential_id TEXT PRIMARY KEY,
  wallet_address TEXT NOT NULL REFERENCES ika_identities(wallet_address) ON DELETE CASCADE,
  public_key_base64 TEXT NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  transports JSONB,
  device_label TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ika_identity_passkeys_wallet_idx
  ON ika_identity_passkeys(wallet_address);

CREATE TABLE IF NOT EXISTS ika_identity_email_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  intent TEXT NOT NULL DEFAULT 'login',
  primary_wallet_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ika_identity_email_tokens_email_idx
  ON ika_identity_email_tokens(email);
CREATE INDEX IF NOT EXISTS ika_identity_email_tokens_expires_idx
  ON ika_identity_email_tokens(expires_at);

CREATE TABLE IF NOT EXISTS ika_identity_oauth_states (
  state TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  intent TEXT NOT NULL DEFAULT 'login',
  primary_wallet_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ika_identity_oauth_states_expires_idx
  ON ika_identity_oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS ika_identity_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  wallet_address TEXT NOT NULL REFERENCES ika_identities(wallet_address) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  user_agent TEXT,
  ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS ika_identity_refresh_tokens_wallet_idx
  ON ika_identity_refresh_tokens(wallet_address);
CREATE INDEX IF NOT EXISTS ika_identity_refresh_tokens_expires_idx
  ON ika_identity_refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS ika_identity_audit (
  id BIGSERIAL PRIMARY KEY,
  wallet_address TEXT,
  event_type TEXT NOT NULL,
  provider TEXT,
  metadata JSONB,
  ip_hash TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ika_identity_audit_wallet_idx
  ON ika_identity_audit(wallet_address);
CREATE INDEX IF NOT EXISTS ika_identity_audit_created_idx
  ON ika_identity_audit(created_at);

CREATE TABLE IF NOT EXISTS ika_identity_config (
  config_key TEXT PRIMARY KEY,
  value_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ika_identity_email_rate_log (
  id BIGSERIAL PRIMARY KEY,
  bucket_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ika_identity_email_rate_log_key_idx
  ON ika_identity_email_rate_log(bucket_key, created_at);
CREATE INDEX IF NOT EXISTS ika_identity_email_rate_log_created_idx
  ON ika_identity_email_rate_log(created_at);

CREATE TABLE IF NOT EXISTS ika_identity_passkey_challenges (
  challenge TEXT PRIMARY KEY,
  challenge_type TEXT NOT NULL,
  user_handle TEXT,
  target_wallet_address TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ika_identity_passkey_challenges_expires_idx
  ON ika_identity_passkey_challenges(expires_at);

-- ─── Recovery Layer ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS recovery_challenges (
  nonce TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  scheme TEXT NOT NULL,
  wallet_address TEXT NOT NULL,
  message TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_challenges_wallet
  ON recovery_challenges(wallet_address, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_rules_policy_state (
  id BIGSERIAL PRIMARY KEY,
  dwallet_address TEXT NOT NULL UNIQUE,
  policy_address TEXT NOT NULL UNIQUE,
  primary_address TEXT NOT NULL,
  primary_curve SMALLINT NOT NULL,
  recovery_members JSONB NOT NULL DEFAULT '[]'::jsonb,
  quorum_threshold SMALLINT NOT NULL DEFAULT 1,
  daily_limit BIGINT,
  allowed_destinations JSONB,
  policy_change_cooldown_seconds BIGINT NOT NULL DEFAULT 604800,
  pending_change JSONB,
  pending_change_activates_at TIMESTAMPTZ,
  on_chain_version BIGINT NOT NULL DEFAULT 0,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recovery_quorum_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dwallet_address TEXT NOT NULL,
  app_id TEXT NOT NULL,
  message_hash BYTEA NOT NULL,
  required_threshold SMALLINT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  finalized_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_quorum_sessions_dwallet
  ON recovery_quorum_sessions(dwallet_address, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_quorum_contributions (
  id BIGSERIAL PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES recovery_quorum_sessions(id) ON DELETE CASCADE,
  member_address TEXT NOT NULL,
  member_curve SMALLINT NOT NULL,
  signature BYTEA NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (session_id, member_address)
);

CREATE TABLE IF NOT EXISTS recovery_signing_ledger (
  id BIGSERIAL PRIMARY KEY,
  dwallet_address TEXT NOT NULL,
  policy_address TEXT NOT NULL,
  recovery_mode TEXT NOT NULL,
  message_hash BYTEA NOT NULL,
  amount BIGINT,
  destination TEXT,
  signers JSONB NOT NULL DEFAULT '[]'::jsonb,
  tx_signature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_signing_ledger_dwallet
  ON recovery_signing_ledger(dwallet_address, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_gas_ledger (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID,
  dwallet_address TEXT,
  policy_address TEXT,
  op_kind TEXT NOT NULL,
  lamports_paid BIGINT NOT NULL,
  tx_signature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_gas_ledger_op
  ON recovery_gas_ledger(op_kind, created_at DESC);

-- Schema migrations bookkeeping (used by migrate.ts)
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
