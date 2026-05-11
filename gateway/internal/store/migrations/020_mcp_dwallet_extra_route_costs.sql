-- Route costs for the additional high-level MCP-facing dWallet ops:
--   POST /v1/dwallet/transfer-ownership → ika.dwallet.transferOwnership
--   POST /v1/dwallet/approve            → ika.dwallet.approve
--
-- `transfer-ownership` and `approve` each build + send one (or two) Solana txs
-- (gas-sponsored) and, for `approve`, drive `recover_as_primary` on-chain. Same
-- tier as the other dWallet ops (T4 = 50). Without these rows the gateway falls
-- back to DEFAULT_REQUEST_COST.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.dwallet.transferOwnership', 50, 'Delegate an MCP dWallet''s authority (transfer_ownership) (T4)'),
    ('ika.dwallet.approve',           50, 'Owner authorises a message for an MCP dWallet (recover_as_primary) (T4)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
