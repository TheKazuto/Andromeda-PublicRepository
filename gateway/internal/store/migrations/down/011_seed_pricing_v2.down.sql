-- Down migration for 011_seed_pricing_v2.sql.
-- Restores plans + request_costs to the values they held BEFORE the
-- v2 economy seed. We deliberately do NOT delete plans rows because
-- subscriptions.plan_id has a FK on them — removing the row would
-- cascade and lose customer state.
--
-- After running this, the seeds from 002_seed_plans.sql and
-- 003_seed_pricing.sql are still in place but with their original
-- (placeholder) values restored.

UPDATE plans SET
    monthly_tokens   = 0,
    rate_limit_rps   = 0,
    rate_limit_burst = 0,
    price_cents      = 0
WHERE code IN ('free', 'pro', 'business', 'premium', 'enterprise');

DELETE FROM request_costs WHERE route_key LIKE 'ika.dkg.%'
  OR route_key LIKE 'ika.recovery.%'
  OR route_key LIKE 'ika.identity.%'
  OR route_key LIKE 'ika.future-sign.%'
  OR route_key LIKE 'ika.re-encrypt-share.%'
  OR route_key LIKE 'ika.make-share-public.%'
  OR route_key LIKE 'ika.presign.%'
  OR route_key LIKE 'ika.sign.%'
  OR route_key LIKE 'ika.presigns.%'
  OR route_key LIKE 'encrypt.%'
  OR route_key LIKE 'mcp.%'
  OR route_key = 'gateway.routes.list';

-- Restore the legacy stub seed from 003_seed_pricing.sql so anything
-- relying on those keys doesn't error out post-rollback.
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.dwallet.create', 1, 'Create a new dWallet'),
    ('ika.dwallet.get',    1, 'Read dWallet metadata'),
    ('ika.dwallet.list',   1, 'List dWallets'),
    ('ika.sign',           1, 'Sign a message'),
    ('mcp.tool.call',      1, 'MCP tool invocation')
ON CONFLICT (route_key) DO NOTHING;
