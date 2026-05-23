-- F2 (Update 5 / mpckit) — Billing ledger for charge/refund idempotency.
--
-- Every token charge and refund is recorded here keyed by a stable op_id so a
-- repeated operation (client retry, network blip, webhook/job replay, MCP
-- loopback) is safe at the DATABASE level, not just at the HTTP idempotency
-- layer (which deliberately does not cache 5xx — exactly the path where a
-- refund runs). The UNIQUE (op_id, kind) constraint is the dedup primitive:
--
--   - charge: ConsumeTokensV2 claims the row; a conflict means the charge
--     already ran, so it replays the stored breakdown without debiting again.
--   - refund: RefundTokensV2 claims the row; a conflict means it was already
--     refunded, so it is a no-op. The charge row's breakdown lets the refund
--     clamp to exactly what was consumed (defense-in-depth).
--
-- IMPORTANT: op_id MUST be caller-scoped before it reaches this table. The REST
-- path builds it as `<subscription_id>:<route_key>:<Idempotency-Key|request_id>`
-- and MCP uses a per-call uuid, so the same client-supplied Idempotency-Key on a
-- different route or from a different tenant is a DISTINCT op (never a collision
-- / cross-tenant breakdown read). The replay/clamp queries additionally filter
-- by subscription_id as defense-in-depth. Never store a raw client key here.
--
-- Forward-only migration (the gateway runner has no down step) — matches the
-- rest of this directory.
CREATE TABLE IF NOT EXISTS token_ledger (
    id              bigserial   PRIMARY KEY,
    op_id           text        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('charge', 'refund')),
    subscription_id text        NOT NULL,
    cost            integer     NOT NULL,
    breakdown       jsonb,      -- serialized ConsumptionResult (charge); lets refund clamp/replay
    applied_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (op_id, kind)
);

CREATE INDEX IF NOT EXISTS token_ledger_sub_idx
    ON token_ledger (subscription_id, applied_at DESC);
