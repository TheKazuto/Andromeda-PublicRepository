-- Update 8 (2026-05-26) — pricing seed for the on-chain session lifecycle
-- routes (discs 100-106 surfaced as REST). Andromeda exposes the primitives
-- so devs can build their own delegation layer; the gateway does not
-- orchestrate per-session state or runtimes. Costs intentionally mirror the
-- rest of the policy admin surface (1 token per challenge/submit).
--
-- Forward-only (the gateway runner has no down step).
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('policy.engine.session.open.challenge',            1, 'Session: open challenge (owner authorizes)'),
    ('policy.engine.session.open.submit',               1, 'Session: open submit (creates Session PDA)'),
    ('policy.engine.session.revoke.challenge',          1, 'Session: revoke challenge (owner force-expires)'),
    ('policy.engine.session.revoke.submit',             1, 'Session: revoke submit'),
    ('policy.engine.session.close.challenge',           1, 'Session: close challenge (rent reclaim)'),
    ('policy.engine.session.close.submit',              1, 'Session: close submit (rent → recipient)'),
    ('policy.engine.session.close-expired',             1, 'Session: permissionless cleanup post-expiry'),
    ('policy.engine.session.destinations.add.challenge',    1, 'Session: add destination challenge'),
    ('policy.engine.session.destinations.add.submit',       1, 'Session: add destination submit'),
    ('policy.engine.session.destinations.remove.challenge', 1, 'Session: remove destination challenge'),
    ('policy.engine.session.destinations.remove.submit',    1, 'Session: remove destination submit'),
    ('policy.engine.session.use.build',                 1, 'Session: build disc 101 instruction (client-pays signing)'),
    ('policy.engine.session.read',                      1, 'Session: read on-chain state')
ON CONFLICT (route_key) DO NOTHING;
