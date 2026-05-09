-- Seed the five plans with placeholder limits.
-- Adjust monthly_tokens, rate_limit_rps, rate_limit_burst and price_cents
-- once costs and pricing are decided. The structure is ready to receive
-- the real values via PATCH /admin/plans/{code} or directly via SQL.

INSERT INTO plans (code, name, monthly_tokens, rate_limit_rps, rate_limit_burst, price_cents, sort_order)
VALUES
    ('free',       'Free',       0, 0, 0, 0, 1),
    ('pro',        'Pro',        0, 0, 0, 0, 2),
    ('business',   'Business',   0, 0, 0, 0, 3),
    ('premium',    'Premium',    0, 0, 0, 0, 4),
    ('enterprise', 'Enterprise', 0, 0, 0, 0, 5)
ON CONFLICT (code) DO NOTHING;
