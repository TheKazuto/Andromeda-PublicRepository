-- Route cost for the passphrase-driven "add quorum recovery member" op:
--   POST /v1/dwallet/admin/add-member → ika.dwallet.adminAddMember
--
-- The engine prepares the on-chain `add_member` admin challenge, signs it with
-- the unwrapped keystore key, and submits one Solana tx (gas-sponsored). Same
-- tier as the other dWallet ops (T4 = 50). Without this row the gateway falls
-- back to DEFAULT_REQUEST_COST.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.dwallet.adminAddMember', 50, 'Add a quorum recovery member to an MCP dWallet (add_member admin action) (T4)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
