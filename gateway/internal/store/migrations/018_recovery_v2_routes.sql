-- Recovery v2 route catalogue alignment.
--
-- The ika-backend recovery surface moved to a challenge-based v2 layout
-- (primary/{challenge,submit}, quorum/session/{open,contribute,finalize,close}
-- each with their own /challenge step, and policy/{preview,deploy,admin/...,
-- apply-pending}). The gateway route catalogue (routes.go) was updated to
-- match; this migration brings request_costs in line so chargeQuota() finds
-- a cost for every new route key and drops the obsolete ones.
--
-- Token tiers (same scale as 011_seed_pricing_v2.sql):
--   T1 = 1   (reads, challenges, status)
--   T2 = 5   (light prepares / session bookkeeping)
--   T3 = 25  (consequential submits / on-chain deploys)
--   T5 = 125 (quorum finalize)

-- Drop the pre-v2 keys that no longer have a route.
DELETE FROM request_costs WHERE route_key IN (
    'ika.recovery.primary.prepare',
    'ika.recovery.quorum.start',
    'ika.recovery.policy.deploy.prepare',
    'ika.recovery.policy.deploy.submit',
    'ika.recovery.policy.change.prepare',
    'ika.recovery.policy.change.apply',
    'ika.recovery.policy.revoke'
);

-- Seed the v2 keys. Existing deployments may have already applied earlier
-- migrations, so upsert.
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.recovery.primary.challenge',            1,  'Recovery primary: challenge (T1)'),
    ('ika.recovery.quorum.open.challenge',        1,  'Recovery quorum: open session challenge (T1)'),
    ('ika.recovery.quorum.open',                  5,  'Recovery quorum: open session (T2)'),
    ('ika.recovery.quorum.contribute.challenge',  1,  'Recovery quorum: contribute challenge (T1)'),
    ('ika.recovery.quorum.close',                 5,  'Recovery quorum: close session (T2)'),
    ('ika.recovery.policy.deploy',                25, 'Recovery policy: deploy (T3)'),
    ('ika.recovery.policy.admin.challenge',       1,  'Recovery policy: admin challenge (T1)'),
    ('ika.recovery.policy.admin.submit',          25, 'Recovery policy: admin submit (T3)'),
    ('ika.recovery.policy.apply-pending',         25, 'Recovery policy: apply pending change (T3)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
