-- P1.5 of the robustness plan: webhook dispatcher leases.
--
-- Today ClaimDeliveries flips rows from `pending` → `in_flight` and the
-- dispatcher relies on a happy-path MarkDelivered/MarkFailed to clear
-- them. If the dispatcher crashes mid-flight, those rows sit forever
-- until a human notices.
--
-- Add explicit lease metadata so a separate sweeper can revert
-- abandoned claims back to `pending`, and the next dispatcher tick
-- picks them up. claim_owner is informational (which replica claimed
-- the row); claim_deadline is the authoritative "this lease expires at
-- timestamp X" signal.

ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS claimed_at     timestamptz NULL,
    ADD COLUMN IF NOT EXISTS claim_deadline timestamptz NULL,
    ADD COLUMN IF NOT EXISTS claim_owner    text        NULL;

-- Find abandoned in_flight rows cheaply during sweeper cycles.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_lease_expired
    ON webhook_deliveries (claim_deadline)
    WHERE status = 'in_flight' AND claim_deadline IS NOT NULL;
