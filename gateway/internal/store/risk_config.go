package store

import (
	"context"
)

// GetRiskConfig retrieves the risk configuration for a dWallet.
// Returns ErrNotFound if no explicit config exists (this is expected and should
// trigger fallback to RiskTenantDefaults in higher-level code).
func (s *pgStore) GetRiskConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error) {
	if err := validateInput(dwalletAddress, "dwalletAddress"); err != nil {
		return nil, err
	}

	var err error
	dwalletAddress, err = NormalizeAddress(dwalletAddress)
	if err != nil {
		return nil, err
	}

	q := `
		SELECT
			dwallet_address, tenant_id, warn_level, block_level, simulation_enabled,
			fail_mode, created_at, updated_at
		FROM risk_config
		WHERE dwallet_address = $1
		LIMIT 1
	`

	var cfg RiskConfig
	row := s.pool.QueryRow(ctx, q, dwalletAddress)
	err = row.Scan(
		&cfg.DwalletAddress, &cfg.TenantID, &cfg.WarnLevel, &cfg.BlockLevel,
		&cfg.SimulationEnabled, &cfg.FailMode, &cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, mapErr(err)
	}

	return &cfg, nil
}

// UpsertRiskConfig creates or replaces a risk config for a dWallet (idempotent).
// Ownership is immutable: on conflict, tenant_id is never reassigned and the
// update only applies when the existing row already belongs to cfg.TenantID
// (a cross-tenant write updates nothing and returns ErrNotFound). Callers (RT2)
// MUST still verify the dWallet->tenant ownership before invoking.
func (s *pgStore) UpsertRiskConfig(ctx context.Context, cfg *RiskConfig) error {
	if err := validateInput(cfg.DwalletAddress, "dwalletAddress"); err != nil {
		return err
	}
	if err := validateInput(cfg.TenantID, "tenantId"); err != nil {
		return err
	}
	if err := validateRiskLevel(cfg.WarnLevel); err != nil {
		return err
	}
	if err := validateRiskLevel(cfg.BlockLevel); err != nil {
		return err
	}
	if err := validateFailMode(cfg.FailMode); err != nil {
		return err
	}

	var err error
	dwalletAddress, err := NormalizeAddress(cfg.DwalletAddress)
	if err != nil {
		return err
	}

	q := `
		INSERT INTO risk_config
			(dwallet_address, tenant_id, warn_level, block_level, simulation_enabled, fail_mode, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, COALESCE($7, now()), COALESCE($8, now()))
		ON CONFLICT (dwallet_address) DO UPDATE SET
			warn_level = EXCLUDED.warn_level,
			block_level = EXCLUDED.block_level,
			simulation_enabled = EXCLUDED.simulation_enabled,
			fail_mode = EXCLUDED.fail_mode,
			updated_at = now()
		WHERE risk_config.tenant_id = EXCLUDED.tenant_id
		RETURNING
			dwallet_address, tenant_id, warn_level, block_level, simulation_enabled,
			fail_mode, created_at, updated_at
	`

	row := s.pool.QueryRow(ctx, q,
		dwalletAddress, cfg.TenantID, cfg.WarnLevel, cfg.BlockLevel,
		cfg.SimulationEnabled, cfg.FailMode, nullableTime(cfg.CreatedAt), nullableTime(cfg.UpdatedAt),
	)

	err = row.Scan(
		&cfg.DwalletAddress, &cfg.TenantID, &cfg.WarnLevel, &cfg.BlockLevel,
		&cfg.SimulationEnabled, &cfg.FailMode, &cfg.CreatedAt, &cfg.UpdatedAt,
	)
	return mapErr(err)
}

// DeleteRiskConfig removes the risk config for a dWallet, scoped to the owning
// tenant. The `tenant_id` filter is deny-by-default tenant isolation: a caller
// can only delete a config that belongs to it. A cross-tenant delete affects 0
// rows (idempotent no-op) instead of wiping another tenant's config.
func (s *pgStore) DeleteRiskConfig(ctx context.Context, dwalletAddress, tenantID string) error {
	if err := validateInput(dwalletAddress, "dwalletAddress"); err != nil {
		return err
	}
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return err
	}

	var err error
	dwalletAddress, err = NormalizeAddress(dwalletAddress)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx,
		`DELETE FROM risk_config WHERE dwallet_address = $1 AND tenant_id = $2`,
		dwalletAddress, tenantID,
	)
	return mapErr(err)
}
