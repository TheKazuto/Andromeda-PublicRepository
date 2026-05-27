-- Intents Sui support (Phase 2 of the LI.FI parity expansion, 2026-05-27).
--
-- 034_intents.sql shipped with a CHECK constraint pinning chain_kind to
-- ('solana','evm') — relaxes it to also accept 'sui' so the intents-backend
-- Sui adapter can persist swap intents on the Sui mainnet (CAIP-2 sui:mainnet,
-- chainId 9270000000000000, Ed25519/EddsaSha512 scheme).
--
-- Also seeds pricing for the new /v1/intents/capabilities and the simulate +
-- swap.challenge routes that 034 missed (they default to DEFAULT_REQUEST_COST
-- otherwise — explicit is safer for the billing audit trail).
--
-- Forward-only (the gateway runner has no down step). Bitcoin (UTXO) is NOT
-- added: LI.FI requires a BIP32 xpub for fromAddress, and the Andromeda dWallet
-- is a single key, so single-address support would need a dWallet v2 with
-- derivation. See Updates Andromeda/Updates intents/_SPIKE_BITCOIN_LIFI.md.

ALTER TABLE intents DROP CONSTRAINT IF EXISTS intents_chain_kind_chk;
ALTER TABLE intents ADD CONSTRAINT intents_chain_kind_chk CHECK (chain_kind IN ('solana','evm','sui'));

-- `intent.capabilities` is a one-shot discovery call (the response shape never
-- changes between requests), so cost is the minimum allowed by the
-- `request_costs_positive` CHECK on the table (1) — same as `intent.chains` /
-- `intent.tokens`.
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('intent.simulate',         1, 'Intents: dry-run swap (preview risk + amounts)'),
    ('intent.swap.challenge',   1, 'Intents: owner-auth challenge (zero-trust)'),
    ('intent.capabilities',     1, 'Intents: list supported chainKinds (discovery)')
ON CONFLICT (route_key) DO NOTHING;
