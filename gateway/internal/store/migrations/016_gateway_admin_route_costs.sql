-- Gateway-native admin surfaces were metered after the M4 split. Existing
-- deployments already applied 011, so this migration backfills their costs.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('gateway.webhooks.admin',     5,  'Gateway: webhook admin operation (T2)'),
    ('gateway.audit.read',         1,  'Gateway: audit log read (T1)'),
    ('gateway.policies.admin',     25, 'Gateway: policy/gas-sponsored admin operation (T3)'),
    ('gateway.future-sign.admin',  5,  'Gateway: future-sign trigger admin operation (T2)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
