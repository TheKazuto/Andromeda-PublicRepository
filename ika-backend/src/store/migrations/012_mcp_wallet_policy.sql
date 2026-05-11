-- B2 — auto-attached rules-policy for MCP-created dWallets.
--
-- When `POST /v1/dwallet/create` runs with `attachRecoveryPolicy`, Andromeda
-- deploys a `rules-policy` for the new dWallet (the keystore key is the
-- policy's `init_authority` and its primary owner) and then `transfer_ownership`
-- delegates the dWallet's authority to that policy program's CPI authority PDA.
-- A delegated dWallet is signable (via `recover_as_primary` — the owner
-- authorises each message) and socially recoverable.
--
-- We record which policy holds the dWallet, the 32-byte `init_authority_hash`
-- (needed to re-derive the policy PDA on every later operation — Audit C2 /
-- Opção 4), and the canonical primary member slot — so sign-as-owner and
-- recovery flows don't have to re-read it from chain.
--
-- All nullable: a dWallet created without `attachRecoveryPolicy`, or one whose
-- attach step did not complete, simply has these NULL.

ALTER TABLE mcp_wallet_keys ADD COLUMN IF NOT EXISTS policy_address             TEXT;
ALTER TABLE mcp_wallet_keys ADD COLUMN IF NOT EXISTS policy_init_authority_hash BYTEA;   -- 32 bytes (sha256 of the 34-byte init_authority slot)
ALTER TABLE mcp_wallet_keys ADD COLUMN IF NOT EXISTS policy_primary_scheme      SMALLINT; -- 0=Ed25519, 1=Secp256k1, 2=Secp256r1, 3=WebAuthn
ALTER TABLE mcp_wallet_keys ADD COLUMN IF NOT EXISTS policy_primary_identifier  BYTEA;   -- length depends on scheme (Ed25519 = 32-byte pubkey)
