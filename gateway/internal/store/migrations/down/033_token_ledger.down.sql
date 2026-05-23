-- Down for 033_token_ledger.sql (Update 5 / F2 billing ledger).
-- The table is new with no foreign-key dependents, so a clean drop fully
-- reverts it. Charge/refund fall back to the pre-ledger behaviour (the
-- per-row GREATEST(...,0) guards still prevent negative counters).
DROP TABLE IF EXISTS token_ledger;
