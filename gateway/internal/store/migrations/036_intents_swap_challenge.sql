-- Update 1 (Intents) follow-up — zero-trust owner-auth challenge.
--
-- Adds explicit pricing for the new POST /v1/intents/swap/challenge route. The
-- catalogue would fall back to DEFAULT_REQUEST_COST without this row, but an
-- explicit entry keeps usage/billing predictable when devs run /v1/util/format-amount
-- or query request_costs.
--
-- No table/state changes are needed for the owner-auth flow: the challenge is
-- derived on-the-fly from the persisted Intent (zero-trust by design — the gateway
-- never stores the owner's signature, only relays the precompile).
--
-- Forward-only (the gateway runner has no down step).
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('intent.swap.challenge', 1, 'Intents: derive the owner-auth challenge for a prepared swap')
ON CONFLICT (route_key) DO NOTHING;
