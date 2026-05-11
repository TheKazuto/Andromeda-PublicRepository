-- Route costs for the high-level MCP-facing dWallet ops (option A2):
--   POST /v1/dwallet/create   → ika.dwallet.create
--   POST /v1/dwallet/presign  → ika.dwallet.presign
--   POST /v1/dwallet/sign     → ika.dwallet.sign
--
-- Same tier as the low-level DKG / sign / presign (T4 = 50): the engine work
-- is the same; the extra server-side cost (Argon2id KDF, the commit poll) is
-- not metered. Without these rows the gateway falls back to DEFAULT_REQUEST_COST.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.dwallet.create',  50, 'Create dWallet (DKG, server-side) (T4)'),
    ('ika.dwallet.presign', 50, 'Allocate a presign for an MCP-created dWallet (T4)'),
    ('ika.dwallet.sign',    50, 'Sign a message with an MCP-created dWallet (T4)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
