-- MCP-created dWallet keys — option A2 (passphrase-wrapped, server-side DKG).
--
-- When a user asks the agent to "create a wallet" (POST /v1/dwallet/create →
-- the MCP tool `create_dwallet`), Andromeda generates the Ed25519 signer key
-- (= the dWallet owner / `intended_chain_sender`), wraps the private seed under
-- a key derived from the user's passphrase (Argon2id + AES-256-GCM), and stores
-- ONLY the ciphertext here. The passphrase and the plaintext key are never
-- persisted. To sign later (or to delegate the dWallet to a rules-policy via
-- `transfer_ownership`), the user supplies the passphrase again; Andromeda
-- unwraps in-memory, uses the key, discards it.
--
-- Lost passphrase != lost wallet: the dWallet's on-chain `rules-policy`
-- (primary owner / quorum) recovers it. Pre-alpha / devnet only — these
-- dWallets are wiped at Alpha 1.

CREATE TABLE IF NOT EXISTS mcp_wallet_keys (
    id                TEXT        PRIMARY KEY,                 -- app-generated UUID
    owner_ref         TEXT        NOT NULL,                    -- api_key_id, or the identity walletAddress when identity is enabled
    dwallet_address   TEXT,                                    -- NULL until DKG completes and the dWallet PDA is derived
    curve             SMALLINT    NOT NULL,                    -- DWalletCurve id (e.g. 2 = Curve25519 for Solana/Ed25519)
    signer_pubkey     BYTEA       NOT NULL,                    -- 32 bytes — the Ed25519 pubkey = dWallet owner / intended_chain_sender
    dwallet_public_key BYTEA,                                 -- the DKG-produced dWallet public key (≠ signer_pubkey); set after DKG; the dWallet PDA is derived from (curve, this)
    wrapped_key       BYTEA       NOT NULL,                    -- AES-256-GCM ciphertext of the 32-byte Ed25519 private seed
    wrap_iv           BYTEA       NOT NULL,                    -- 12 bytes (GCM nonce)
    wrap_tag          BYTEA       NOT NULL,                    -- 16 bytes (GCM auth tag)
    kdf_salt          BYTEA       NOT NULL,                    -- 16 bytes, per-record
    kdf_params        JSONB       NOT NULL,                    -- { alg, t, m, p, dkLen } — so KDF params can evolve without re-wrapping everyone
    attestation_data  BYTEA,                                  -- NetworkSignedAttestation.attestation_data — set after DKG; required for every later Sign
    network_signature BYTEA,                                  -- NetworkSignedAttestation.network_signature
    network_pubkey    BYTEA,                                  -- NetworkSignedAttestation.network_pubkey
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_wallet_keys_owner ON mcp_wallet_keys(owner_ref);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_wallet_keys_dwallet ON mcp_wallet_keys(dwallet_address) WHERE dwallet_address IS NOT NULL;
