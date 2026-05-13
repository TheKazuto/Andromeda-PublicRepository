-- Login Social (RulesPolicy OIDC primary; scheme = 4; loginsocial.md §10).
-- Initial per-route token costs for the gateway-proxied OIDC recovery routes.
-- Without these rows the gateway falls back to DEFAULT_REQUEST_COST.
--
--   stage          → oidc_jwt_stage                       (tx; writes a ~4 KiB temp PDA)        25
--   open/challenge  → read (challenge for the eph key)                                            5
--   open           → oidc_session_open (RSA verify on-chain ~55–70k CU + creates the session)    75
--   use/challenge  → read (per-use challenge)                                                     5
--   use/submit     → recover_as_primary_oidc_session (+ CPI Ika approve_message)                 75
--   close          → oidc_session_close (rent refund)                                             25
--   staging/close  → oidc_jwt_staging_close (rent refund of an abandoned staging)                 25
--   /v1/oidc/nonce    → server picks not_after + nonce_randomness, returns oidc_nonce               5
--   /v1/oidc/validate → server-side JWKS pre-check (no chain write)                                5

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.oidc.nonce',                             5, 'Login Social: derive the canonical oidc_nonce for the OAuth handshake'),
    ('ika.recovery.primary.oidc.stage',           25, 'Login Social: stage id_token into a temp PDA (oidc_jwt_stage)'),
    ('ika.recovery.primary.oidc.open.challenge',   5, 'Login Social: challenge for the ephemeral key to open a session'),
    ('ika.recovery.primary.oidc.open',            75, 'Login Social: open an OidcSession (on-chain RSA verify + session PDA)'),
    ('ika.recovery.primary.oidc.use.challenge',    5, 'Login Social: per-use challenge for the ephemeral key'),
    ('ika.recovery.primary.oidc.use.submit',      75, 'Login Social: authorize a signature via an OidcSession (CPI Ika approve_message)'),
    ('ika.recovery.primary.oidc.close',           25, 'Login Social: close an expired OidcSession (rent refund)'),
    ('ika.recovery.primary.oidc.staging.close',   25, 'Login Social: close an abandoned OidcJwtStaging (rent refund)'),
    ('ika.oidc.validate',                          5, 'Login Social: server-side id_token pre-validation (JWKS)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
