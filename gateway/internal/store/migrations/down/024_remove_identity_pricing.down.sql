-- Down migration 024 — restore the Identity Layer pricing rows.
--
-- Inverse of 024_remove_identity_pricing.sql. Keeps the request_costs table in
-- the same shape it had between migrations 011 and 024 in case we ever need to
-- roll back the Identity Layer retirement.

INSERT INTO request_costs(route_key, cost_tokens, description) VALUES
    ('ika.identity.email.request', 5, 'Identity: email magic-link request (T2)'),
    ('ika.identity.email.verify',  5, 'Identity: email magic-link verify (T2)')
ON CONFLICT (route_key) DO UPDATE
    SET cost_tokens = EXCLUDED.cost_tokens,
        description = EXCLUDED.description;
