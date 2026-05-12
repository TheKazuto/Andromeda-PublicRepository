-- Discovery enumeration index.
--
-- `POST /v1/recovery/resolve` proves ownership of an external wallet and then
-- enumerates the Andromeda-managed dWallets whose attached rules-policy has
-- that wallet as its primary owner. The lookup keys on
-- (policy_primary_scheme, policy_primary_identifier) and only ever wants rows
-- that have completed DKG (dwallet_address IS NOT NULL).

CREATE INDEX IF NOT EXISTS idx_mcp_wallet_keys_primary_owner
    ON mcp_wallet_keys (policy_primary_scheme, policy_primary_identifier)
    WHERE dwallet_address IS NOT NULL AND policy_primary_identifier IS NOT NULL;
