-- F7.5 — route cost for the managed oracle price-trigger admin endpoints
-- (/v1/oracle/triggers). Same tier as the future-sign trigger admin op (T2 = 5):
-- arming/cancelling a trigger is a cheap DB write; the metered on-chain work
-- (request_signature) happens at fire time and is gas-sponsored. Without this
-- row the gateway falls back to DEFAULT_REQUEST_COST.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('gateway.oracle-triggers.admin', 5, 'Gateway: oracle price-trigger admin operation (T2)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
