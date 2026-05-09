-- Future-Sign trigger watcher (Sprint 4 — Andromeda Features Roadmap §2).
--
-- Devs arm a trigger that watches an off-chain or on-chain condition. When the
-- condition fires, the gateway calls /v1/dwallet/future-sign/complete/submit on
-- the ika-backend, captures the raw signature, and fans the result out via the
-- existing webhook pipeline.

DO $$ BEGIN
    CREATE TYPE future_sign_trigger_type AS ENUM (
        'oracle_pyth',
        'oracle_switchboard',
        'solana_event',
        'slot_time',
        'external_webhook'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE future_sign_trigger_status AS ENUM (
        'armed',
        'firing',
        'fired',
        'expired',
        'cancelled',
        'failed'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS future_sign_triggers (
    id                  uuid                          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id          uuid                          NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    partial_sig_cap_id  text                          NOT NULL,
    dwallet_address     text                          NOT NULL,
    policy_program_id   text,
    trigger_type        future_sign_trigger_type      NOT NULL,
    condition           jsonb                         NOT NULL,
    webhook_url         text                          NOT NULL,
    status              future_sign_trigger_status    NOT NULL DEFAULT 'armed',
    created_at          timestamptz                   NOT NULL DEFAULT now(),
    expires_at          timestamptz                   NOT NULL,
    fired_at            timestamptz,
    signature_hex       text,
    last_check_slot     bigint,
    last_check_at       timestamptz,
    failure_count       int                           NOT NULL DEFAULT 0,
    last_error          text,
    -- Pre-built complete-submit payload that the watcher posts to the ika-backend
    -- when the trigger fires. Must be supplied at arming time by the dev — the
    -- gateway never builds or signs partial-user signatures itself.
    complete_payload    jsonb                         NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_triggers_armed
    ON future_sign_triggers(status, expires_at)
    WHERE status = 'armed';

CREATE INDEX IF NOT EXISTS idx_triggers_api_key
    ON future_sign_triggers(api_key_id, created_at DESC);
