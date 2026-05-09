-- =============================================================================
-- Idempotency safety net for gift card webhook handlers.
--
-- Stripe webhooks can be redelivered. The dedupe table on stripe_events
-- handles that at the event-id level, but if a worker crashes between
-- "row inserted" and "event marked processed", we'd risk double-inserts
-- on retry. A unique partial index on stripe_payment_id closes the loop:
-- the handler can use ON CONFLICT to no-op on retries.
-- =============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_gift_cards_stripe_payment_id
  ON gift_cards(stripe_payment_id)
  WHERE stripe_payment_id IS NOT NULL;
