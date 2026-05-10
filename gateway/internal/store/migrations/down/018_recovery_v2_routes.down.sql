-- Down migration for 018_recovery_v2_routes.sql.
-- Restores the pre-v2 recovery route_costs and removes the v2 keys.
-- Run before rolling back the routes.go change, and then:
--   DELETE FROM schema_migrations WHERE version = 18;

DELETE FROM request_costs WHERE route_key IN (
    'ika.recovery.primary.challenge',
    'ika.recovery.quorum.open.challenge',
    'ika.recovery.quorum.open',
    'ika.recovery.quorum.contribute.challenge',
    'ika.recovery.quorum.close',
    'ika.recovery.policy.deploy',
    'ika.recovery.policy.admin.challenge',
    'ika.recovery.policy.admin.submit',
    'ika.recovery.policy.apply-pending'
);

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.recovery.primary.prepare',        5,  'Recovery primary: prepare (T2)'),
    ('ika.recovery.quorum.start',           5,  'Recovery quorum: start session (T2)'),
    ('ika.recovery.policy.deploy.prepare',  5,  'Recovery policy: deploy prepare (T2)'),
    ('ika.recovery.policy.deploy.submit',   25, 'Recovery policy: deploy submit (T3)'),
    ('ika.recovery.policy.change.prepare',  5,  'Recovery policy: change prepare (T2)'),
    ('ika.recovery.policy.change.apply',    25, 'Recovery policy: change apply (T3)'),
    ('ika.recovery.policy.revoke',          25, 'Recovery policy: revoke (T3)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
