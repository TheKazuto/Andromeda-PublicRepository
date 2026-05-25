-- Update 1 (Intents) follow-ups — EVM nonce safety + ERC20 two-step approve.
--
-- evm_nonce: the swap tx nonce, persisted so the orchestrator can enforce a
-- single in-flight EVM swap per (dwallet, chain) and reconcile by nonce.
-- approve_*: an optional ERC20 approve tx that must be signed, broadcast and
-- confirmed BEFORE the swap (it sits one nonce below the swap).
--
-- Forward-only (the gateway runner has no down step). 034 has not been applied
-- in any environment yet, but migrations are append-only, so this is a 035.
ALTER TABLE intents ADD COLUMN IF NOT EXISTS evm_nonce numeric;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS approve_unsigned_tx bytea;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS approve_message bytea;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS approve_message_digest text;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS approve_tx_hash text;

-- Add the APPROVING state (ERC20 approve broadcast, waiting to confirm + swap).
ALTER TABLE intents DROP CONSTRAINT IF EXISTS intents_status_chk;
ALTER TABLE intents ADD CONSTRAINT intents_status_chk CHECK (status IN
  ('PREPARED','AUTHORIZING','APPROVING','SIGNING','BROADCASTING','SUBMITTED','BROADCAST_UNKNOWN','SUBMITTED_UNKNOWN','CONFIRMED','SETTLED','FAILED','EXPIRED','CANCELLED'));

-- Backs the single-in-flight-EVM-swap guard (one open swap per dwallet+chain).
CREATE INDEX IF NOT EXISTS idx_intents_evm_inflight ON intents(user_id, chain_native_address, chain_id)
  WHERE chain_kind = 'evm' AND status NOT IN ('SETTLED','FAILED','EXPIRED','CANCELLED');

-- Pricing for the simulate preview (Fase 5).
INSERT INTO request_costs (route_key, cost_tokens, description) VALUES
    ('intent.simulate', 1, 'Intents: simulate a swap (preview route/fees/risk, no intent)')
ON CONFLICT (route_key) DO NOTHING;
