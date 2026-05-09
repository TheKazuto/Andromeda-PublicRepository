-- Maps every deployed Andromeda policy PDA back to the api_key_id that owns
-- it, so the Solana log listener (Phase 2) can fan events out to the right
-- tenant's webhook endpoints.
--
-- A row is inserted whenever the gateway prepares a successful init for a
-- policy template (see /v1/policies/{template}/init/submit). The same
-- (api_key_id, policy_address) tuple is unique — re-runs of init are
-- idempotent.

CREATE TABLE IF NOT EXISTS policy_subscriptions (
    policy_address    text         PRIMARY KEY,
    api_key_id        uuid         NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    template          text         NOT NULL,
    program_id        text         NOT NULL,
    dwallet_address   text         NOT NULL,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    last_event_at     timestamptz
);

CREATE INDEX IF NOT EXISTS idx_policy_subs_api_key
    ON policy_subscriptions(api_key_id, created_at DESC);
