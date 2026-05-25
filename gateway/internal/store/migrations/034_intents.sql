-- Update 1 (Intents) — swap intent state. The gateway owns this table; the
-- intents-backend is stateless. One row per swap intent, carrying a verifiable
-- snapshot of the prepared transaction so submit can re-derive and match the
-- signing material byte-for-byte before authorizing.
--
-- Sensitive material note: sign_message / message_metadata / unsigned_tx are
-- financial material (not private keys, but the exact bytes that get signed).
-- Never log them, never expose them in listings — internal use only. The
-- passphrase and raw signature are NEVER persisted here.
--
-- Forward-only migration (the gateway runner has no down step).
CREATE TABLE IF NOT EXISTS intents (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id              uuid,
    kind                    text NOT NULL DEFAULT 'swap',          -- swap | (future: limit, dca)
    chain_kind              text NOT NULL,                          -- 'solana' | 'evm'
    from_chain              text NOT NULL,
    to_chain                text NOT NULL,
    from_token              text NOT NULL,
    to_token                text NOT NULL,
    from_amount             numeric NOT NULL,
    quoted_amount_out       numeric,
    quoted_amount_out_min   numeric,
    ika_dwallet_address     text NOT NULL,                          -- dWallet Solana/Ika address
    dwallet_public_key_hex  text NOT NULL,                          -- curve key used by prepare-message/address derivation + sign
    owner_pubkey_hex        text NOT NULL,                          -- dWallet owner pubkey (hex32) — request-signature binding
    init_authority_hash_hex text NOT NULL,                          -- PolicyEngine init authority hash (hex32)
    ika_curve               smallint NOT NULL DEFAULT 2,            -- Ika curve id (2 = Curve25519 / Solana)
    chain_native_address    text NOT NULL,                          -- address on destination chain (== fee payer)
    chain_id                text NOT NULL,                          -- numeric LI.FI id used by broadcast
    sign_chain_id           text NOT NULL,                          -- CAIP-2 id for ika prepare-message (e.g. solana:...)
    status                  text NOT NULL DEFAULT 'PREPARED',
    sign_scheme             smallint NOT NULL,
    sign_message            bytea NOT NULL,                         -- = preprocessedHex (bytes sent to ika /sign); never log
    message_digest          text NOT NULL,                         -- = digestHex = keccak256(preprocessed); approved by PolicyEngine
    message_metadata        bytea NOT NULL DEFAULT '\x',            -- = messageMetadataHex; empty for Solana
    ika_msg_metadata_digest text NOT NULL,                          -- = ikaMsgMetadataDigestHex (32×0 for Solana)
    policy_metadata_digest  text NOT NULL,                          -- request-signature challenge digest; presign harvest key
    unsigned_tx             bytea NOT NULL,                         -- LI.FI prepared-tx snapshot; never expose in listings
    unsigned_tx_hash        text NOT NULL,                          -- sha256 of unsigned_tx for snapshot integrity
    route_snapshot          jsonb NOT NULL DEFAULT '{}'::jsonb,     -- LI.FI route + verified fields
    risk_snapshot           jsonb NOT NULL DEFAULT '{}'::jsonb,     -- advisory + simulation summary (never blocks)
    approval_tx_sig         text,                                   -- PolicyEngine approve tx signature (base58)
    approval_slot           bigint,                                 -- slot of the approval tx
    presign_session_id      text,                                   -- presign harvested at submit
    swap_tx_hash            text,                                   -- broadcast swap tx hash
    lifi_route_id           text,
    confirmation_slot       bigint,
    confirmed_at            timestamptz,
    webhook_sent_at         timestamptz,
    locked_at               timestamptz,
    lock_owner              text,
    error                   text,                                   -- sanitized
    expires_at              timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT intents_status_chk CHECK (status IN
        ('PREPARED','AUTHORIZING','SIGNING','BROADCASTING','SUBMITTED','BROADCAST_UNKNOWN','SUBMITTED_UNKNOWN','CONFIRMED','SETTLED','FAILED','EXPIRED','CANCELLED')),
    CONSTRAINT intents_chain_kind_chk CHECK (chain_kind IN ('solana','evm'))
);

CREATE INDEX IF NOT EXISTS idx_intents_user ON intents(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intents_status_open ON intents(status, updated_at)
    WHERE status NOT IN ('SETTLED','FAILED','EXPIRED','CANCELLED');
CREATE INDEX IF NOT EXISTS idx_intents_dwallet_chain_open ON intents(user_id, chain_native_address, chain_id, status)
    WHERE status IN ('PREPARED','AUTHORIZING','SIGNING','BROADCASTING','SUBMITTED','BROADCAST_UNKNOWN','SUBMITTED_UNKNOWN');

-- Pricing seed for the intents surface. New routes fall back to
-- DEFAULT_REQUEST_COST when absent; these make the costs explicit.
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('intent.quote',        1, 'Intents: swap quote (preview)'),
    ('intent.chains',       1, 'Intents: supported chains'),
    ('intent.tokens',       1, 'Intents: tokens per chain'),
    ('intent.swap.prepare', 1, 'Intents: prepare a swap (build tx + intent)'),
    ('intent.swap.submit',  1, 'Intents: authorize, sign and broadcast a swap'),
    ('intent.status',       1, 'Intents: read swap intent status')
ON CONFLICT (route_key) DO NOTHING;
