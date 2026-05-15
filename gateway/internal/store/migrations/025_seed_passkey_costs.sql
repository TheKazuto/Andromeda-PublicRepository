-- Passkey-PRF (RulesPolicy WebAuthn primary; scheme = 3 session-scoped;
-- PLAN_KEYSPRING_INTEGRATION_2026_05.md D8). Initial per-route token costs
-- for the gateway-proxied passkey recovery routes. Without these rows the
-- gateway falls back to DEFAULT_REQUEST_COST.
--
--   credentials/register-init       → server-issued register challenge (off-chain only)        5
--   credentials/register-complete   → consume challenge + persist credential (DB, no chain)   10
--   credentials                      → list active credentials                                  5
--   credentials/{id}/revoke         → D5 guard + revoke row (no chain write)                  10
--   open/challenge                  → derive passkey_session_open_challenge                    5
--   open                            → passkey_session_open (Secp256r1 precompile + ix 25)    50
--   use/challenge                   → derive passkey_primary_use_challenge                     5
--   use/submit                      → recover_as_primary_passkey_session + CPI Ika           75
--   close                           → passkey_session_close (rent refund)                    25
--   capabilities                    → static config echo                                       5

INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('ika.recovery.primary.passkey.credentials.register-init',     5,  'Passkey: server-issued register challenge (UUID + 32-byte nonce, single-use)'),
    ('ika.recovery.primary.passkey.credentials.register-complete', 10, 'Passkey: persist credential under dWallet (D6 limit 5/dwallet enforced in tx)'),
    ('ika.recovery.primary.passkey.credentials.list',              5,  'Passkey: list active credentials on a dWallet'),
    ('ika.recovery.primary.passkey.credentials.revoke',            10, 'Passkey: revoke credential (D5 last-active-method guard)'),
    ('ika.recovery.primary.passkey.open.challenge',                5,  'Passkey: challenge for the WebAuthn assertion that opens a session'),
    ('ika.recovery.primary.passkey.open',                          50, 'Passkey: open a PasskeySession (Secp256r1 precompile + session PDA)'),
    ('ika.recovery.primary.passkey.use.challenge',                 5,  'Passkey: per-use challenge for the ephemeral Ed25519 key'),
    ('ika.recovery.primary.passkey.use.submit',                    75, 'Passkey: authorize a signature via PasskeySession (CPI Ika approve_message)'),
    ('ika.recovery.primary.passkey.close',                         25, 'Passkey: close an expired PasskeySession (rent refund)'),
    ('ika.recovery.primary.passkey.capabilities',                  5,  'Passkey: static config echo (rp_id, salt mode, TTLs, on-chain bounds)')
ON CONFLICT (route_key) DO UPDATE SET
    cost_tokens = EXCLUDED.cost_tokens,
    description = EXCLUDED.description,
    updated_at  = now();
