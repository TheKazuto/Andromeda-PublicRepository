-- Seed default request costs. Every catalogued route starts at 1 token.
-- Adjust per-route via PATCH /admin/request-costs/{routeKey} once the
-- real cost-per-call has been measured against ika-backend / encrypt-backend.
--
-- New routes added later in routes/routes.go will fall back to
-- DEFAULT_REQUEST_COST (env, default 1) when not present here.

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.dwallet.create',          1, 'Create a new dWallet'),
    ('ika.dwallet.get',             1, 'Read dWallet metadata'),
    ('ika.dwallet.list',            1, 'List dWallets'),
    ('ika.sign',                    1, 'Sign a message'),
    ('ika.presign',                 1, 'Generate presignature'),
    ('ika.future-sign',             1, 'Future-sign'),
    ('ika.recover.challenge',       1, 'Recovery: request challenge'),
    ('ika.recover.resolve',         1, 'Recovery: resolve identity'),
    ('ika.identity.email.request',  1, 'Identity: email magic-link request'),
    ('ika.identity.email.verify',   1, 'Identity: email magic-link verify'),
    ('encrypt.private-tx.prepare',  1, 'Encrypt: prepare private transaction'),
    ('encrypt.private-tx.submit',   1, 'Encrypt: submit signed private transaction'),
    ('encrypt.graph.execute',       1, 'Encrypt: execute graph'),
    ('encrypt.graph.read',          1, 'Encrypt: read ciphertext'),
    ('encrypt.nek.read',            1, 'Encrypt: read NEK'),
    ('mcp.tool.call',               1, 'MCP tool invocation')
ON CONFLICT (route_key) DO NOTHING;
