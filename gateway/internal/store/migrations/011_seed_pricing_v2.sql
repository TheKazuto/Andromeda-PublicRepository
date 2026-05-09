-- =============================================================================
-- Seed v2 — applies the approved economy:
--
--   * Token rate (symbolic): 1.000 tokens ≈ $4 → 1 token = $0.004
--   * 5 plans:
--       Free       2.000 tokens   $0       read 10/20      tx 1/2
--       Pro        15.000 tokens  $49      read 50/100     tx 5/10
--       Business   160.000 tokens $499     read 200/400    tx 50/100
--       Premium    350.000 tokens $999     read 500/1000   tx 100/200
--       Enterprise (custom — seeded with placeholder; provisioned per
--                  customer via /admin once the contract is signed)
--   * Annual = 10× monthly (16.67% off)
--   * Overage rate: $4/1k → 400 cents per 1.000 tokens
--   * Route costs: 5 tiers (1/5/25/50/125)
--
-- Re-run safe: ON CONFLICT (code) DO UPDATE keeps live values aligned with
-- this seed. If you want to override per-environment, run PATCH /admin/plans
-- AFTER deploy — those become the source of truth and won't be overwritten
-- on the next migration (this file is applied only once, by version 011).
-- =============================================================================

-- ----- plans -----
INSERT INTO plans (
    code, name,
    monthly_tokens, price_cents, annual_price_cents,
    rate_limit_rps, rate_limit_burst,           -- legacy single bucket
    read_rps, read_burst, tx_rps, tx_burst,
    overage_per_1k_cents,
    is_active, is_giftable, sort_order, features
) VALUES
    -- Free: gateway/landing tier. 1 dWallet/month cap is enforced at app
    -- level (not DB) because it requires read of the dwallets table.
    ('free', 'Free',
        2000, 0, 0,
        1, 2,                                    -- legacy mirror = tx values
        10, 20, 1, 2,
        0,                                       -- overage disabled
        true, false, 1,
        '{"webhooks":false,"audit":false,"policies":false,"future_sign":false,"recovery_quorum":false,"mainnet":false,"priority_support":false,"custom_rates":false,"max_dwallets":1,"inactivity_wipe_days":60}'::jsonb),

    -- Pro: indie dev, MVP. ~300 signs/month.
    ('pro', 'Pro',
        15000, 4900, 49000,                      -- $49/mo, $490/yr (10× = 2 months free)
        5, 10,
        50, 100, 5, 10,
        400,                                     -- $4/1k overage
        true, true, 2,
        '{"webhooks":true,"audit":true,"policies":false,"future_sign":true,"recovery_quorum":false,"mainnet":true,"priority_support":false,"custom_rates":false}'::jsonb),

    -- Business: startup with prod app. ~3.200 signs/month.
    ('business', 'Business',
        160000, 49900, 499000,                   -- $499/mo, $4.990/yr
        50, 100,
        200, 400, 50, 100,
        400,
        true, true, 3,
        '{"webhooks":true,"audit":true,"policies":true,"future_sign":true,"recovery_quorum":true,"mainnet":true,"priority_support":false,"custom_rates":false,"confidential_workflows":true}'::jsonb),

    -- Premium: scaling app. ~7.000 signs/month.
    ('premium', 'Premium',
        350000, 99900, 999000,                   -- $999/mo, $9.990/yr
        100, 200,
        500, 1000, 100, 200,
        400,
        true, true, 4,
        '{"webhooks":true,"audit":true,"policies":true,"future_sign":true,"recovery_quorum":true,"mainnet":true,"priority_support":true,"custom_rates":false,"confidential_workflows":true,"sla_99_9":true,"custom_domains":true}'::jsonb),

    -- Enterprise: pay-as-you-go above $1.999. Numbers below are the
    -- minimum-purchase floor; admin sets the actual values per contract.
    ('enterprise', 'Enterprise',
        1000000, 199900, 199900,                 -- $1.999 minimum, no annual cycle
        200, 400,
        1000, 2000, 200, 400,
        200,                                     -- $2/1k overage (50% off)
        true, false, 5,
        '{"webhooks":true,"audit":true,"policies":true,"future_sign":true,"recovery_quorum":true,"mainnet":true,"priority_support":true,"custom_rates":true,"confidential_workflows":true,"sla_99_9":true,"custom_domains":true,"dedicated_infra":true,"security_review":true}'::jsonb)
ON CONFLICT (code) DO UPDATE SET
    name                 = EXCLUDED.name,
    monthly_tokens       = EXCLUDED.monthly_tokens,
    price_cents          = EXCLUDED.price_cents,
    annual_price_cents   = EXCLUDED.annual_price_cents,
    rate_limit_rps       = EXCLUDED.rate_limit_rps,
    rate_limit_burst     = EXCLUDED.rate_limit_burst,
    read_rps             = EXCLUDED.read_rps,
    read_burst           = EXCLUDED.read_burst,
    tx_rps               = EXCLUDED.tx_rps,
    tx_burst             = EXCLUDED.tx_burst,
    overage_per_1k_cents = EXCLUDED.overage_per_1k_cents,
    is_active            = EXCLUDED.is_active,
    is_giftable          = EXCLUDED.is_giftable,
    sort_order           = EXCLUDED.sort_order,
    features             = EXCLUDED.features,
    updated_at           = now();

-- ----- request_costs (5 tiers, mapped to the 46 routes in routes.go) -----
-- Tier reference:
--   T1 = 1   token  (reads / poll / status)
--   T2 = 5   tokens (prepare / identity)
--   T3 = 25  tokens (submit common)
--   T4 = 50  tokens (DKG / sign / presign / re-encrypt-share)
--   T5 = 125 tokens (future-sign / quorum finalize)
--
-- Wipe legacy seed (003_seed_pricing.sql had outdated route keys) before
-- applying the v2 catalogue.
DELETE FROM request_costs WHERE route_key IN (
    'ika.dwallet.create','ika.dwallet.get','ika.dwallet.list',
    'ika.sign','ika.presign','ika.future-sign',
    'ika.recover.challenge','ika.recover.resolve',
    'ika.identity.email.request','ika.identity.email.verify',
    'encrypt.private-tx.prepare','encrypt.private-tx.submit',
    'encrypt.graph.execute','encrypt.graph.read','encrypt.nek.read',
    'mcp.tool.call'
);

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    -- ika-backend: dWallet lifecycle
    ('ika.dkg.prepare',                         5,  'DKG: prepare unsigned tx (T2)'),
    ('ika.dkg.submit',                          50, 'DKG: submit signed tx → MPC engine (T4)'),
    ('ika.presigns.list',                       1,  'List presigns (T1)'),
    ('ika.sign.submit',                         50, 'Sign: submit → MPC engine (T4)'),
    ('ika.presign.submit',                      50, 'Presign: submit → MPC engine (T4)'),
    ('ika.future-sign.submit',                  125,'Future-sign: submit → MPC engine (T5)'),
    ('ika.future-sign.complete.submit',         125,'Future-sign complete: submit (T5)'),
    ('ika.re-encrypt-share.submit',             25, 'Re-encrypt share: submit (T3)'),
    ('ika.make-share-public.submit',            25, 'Make share public: submit (T3)'),

    -- ika-backend: recovery
    ('ika.recovery.challenge',                  1,  'Recovery: challenge (T1)'),
    ('ika.recovery.resolve',                    5,  'Recovery: resolve (T2)'),
    ('ika.recovery.primary.prepare',            5,  'Recovery primary: prepare (T2)'),
    ('ika.recovery.primary.submit',             25, 'Recovery primary: submit (T3)'),
    ('ika.recovery.quorum.start',               5,  'Recovery quorum: start session (T2)'),
    ('ika.recovery.quorum.contribute',          5,  'Recovery quorum: contribute (T2)'),
    ('ika.recovery.quorum.get',                 1,  'Recovery quorum: get session (T1)'),
    ('ika.recovery.quorum.finalize',            125,'Recovery quorum: finalize (T5)'),
    ('ika.recovery.policy.preview',             1,  'Recovery policy: preview (T1)'),
    ('ika.recovery.policy.deploy.prepare',      5,  'Recovery policy: deploy prepare (T2)'),
    ('ika.recovery.policy.deploy.submit',       25, 'Recovery policy: deploy submit (T3)'),
    ('ika.recovery.policy.get',                 1,  'Recovery policy: get (T1)'),
    ('ika.recovery.policy.change.prepare',      5,  'Recovery policy: change prepare (T2)'),
    ('ika.recovery.policy.change.apply',        25, 'Recovery policy: change apply (T3)'),
    ('ika.recovery.policy.revoke',              25, 'Recovery policy: revoke (T3)'),

    -- ika-backend: identity (opt-in)
    ('ika.identity.email.request',              5,  'Identity: email magic-link request (T2)'),
    ('ika.identity.email.verify',               5,  'Identity: email magic-link verify (T2)'),

    -- encrypt-backend: private transactions
    ('encrypt.private-tx.submit',               25, 'Encrypt: private-tx submit (T3)'),
    ('encrypt.private-tx.status',               1,  'Encrypt: private-tx status (T1)'),

    -- encrypt-backend: ciphertexts
    ('encrypt.ciphertext.create',               25, 'Encrypt: ciphertext create (T3)'),
    ('encrypt.ciphertext.read',                 1,  'Encrypt: ciphertext read (T1)'),
    ('encrypt.ciphertext.account.get',          1,  'Encrypt: ciphertext account get (T1)'),

    -- encrypt-backend: graphs
    ('encrypt.graph.execute.prepare',           5,  'Encrypt: graph execute prepare (T2)'),
    ('encrypt.graph.register.prepare',          5,  'Encrypt: graph register prepare (T2)'),
    ('encrypt.graph.execute-registered.prepare',5,  'Encrypt: graph execute-registered prepare (T2)'),
    ('encrypt.graph.commit.prepare',            5,  'Encrypt: graph commit prepare (T2)'),
    ('encrypt.graph.submit',                    25, 'Encrypt: graph submit (T3)'),
    ('encrypt.graph.status',                    1,  'Encrypt: graph status (T1)'),
    ('encrypt.graph.operations.list',           1,  'Encrypt: graph operations list (T1)'),
    ('encrypt.graph.operations.register-bytes', 25, 'Encrypt: graph operations register-bytes (T3)'),

    -- encrypt-backend: DSL
    ('encrypt.dsl.types',                       1,  'Encrypt: DSL types (T1)'),
    ('encrypt.dsl.op.prepare',                  5,  'Encrypt: DSL op prepare (T2)'),

    -- encrypt-backend: decrypt
    ('encrypt.decrypt.request.prepare',         5,  'Encrypt: decrypt request prepare (T2)'),
    ('encrypt.decrypt.poll',                    1,  'Encrypt: decrypt poll (T1)'),

    -- encrypt-backend: NEK / events / wallet
    ('encrypt.nek.current',                     1,  'Encrypt: NEK current (T1)'),
    ('encrypt.events.emit.prepare',             5,  'Encrypt: events emit prepare (T2)'),
    ('encrypt.events.by-signature',             1,  'Encrypt: events by-signature (T1)'),
    ('encrypt.wallet.balance.init',             25, 'Encrypt: wallet balance init (T3)'),

    -- encrypt-backend: authority / fees / ownership (all prepares = T2)
    ('encrypt.authority.add.prepare',           5,  'Encrypt: authority add prepare (T2)'),
    ('encrypt.authority.remove.prepare',        5,  'Encrypt: authority remove prepare (T2)'),
    ('encrypt.authority.register-nek.prepare',  5,  'Encrypt: authority register-NEK prepare (T2)'),
    ('encrypt.fees.deposit.create.prepare',     5,  'Encrypt: fees deposit create prepare (T2)'),
    ('encrypt.fees.deposit.top-up.prepare',     5,  'Encrypt: fees deposit top-up prepare (T2)'),
    ('encrypt.fees.deposit.withdraw.prepare',   5,  'Encrypt: fees deposit withdraw prepare (T2)'),
    ('encrypt.fees.deposit.request-withdraw.prepare', 5, 'Encrypt: fees deposit request-withdraw prepare (T2)'),
    ('encrypt.fees.deposit.reimburse.prepare',  5,  'Encrypt: fees deposit reimburse prepare (T2)'),
    ('encrypt.fees.config.update.prepare',      5,  'Encrypt: fees config update prepare (T2)'),
    ('encrypt.ownership.transfer.prepare',      5,  'Encrypt: ownership transfer prepare (T2)'),
    ('encrypt.ownership.copy.prepare',          5,  'Encrypt: ownership copy prepare (T2)'),
    ('encrypt.ownership.make-public.prepare',   5,  'Encrypt: ownership make-public prepare (T2)'),

    -- MCP gateway methods
    ('mcp.initialize',                          1,  'MCP: initialize (T1)'),
    ('mcp.tools.list',                          1,  'MCP: tools/list (T1)'),
    ('mcp.ping',                                1,  'MCP: ping (T1)'),
    ('gateway.routes.list',                     1,  'MCP: gateway.routes.list (T1)'),

    -- Gateway-native admin surfaces
    ('gateway.webhooks.admin',                  5,  'Gateway: webhook admin operation (T2)'),
    ('gateway.audit.read',                      1,  'Gateway: audit log read (T1)'),
    ('gateway.policies.admin',                  25, 'Gateway: policy/gas-sponsored admin operation (T3)'),
    ('gateway.future-sign.admin',               5,  'Gateway: future-sign trigger admin operation (T2)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
