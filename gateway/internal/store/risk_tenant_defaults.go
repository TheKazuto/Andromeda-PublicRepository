package store

import (
	"context"
)

// GetRiskTenantDefaults retrieves the default risk policy for a tenant.
// Returns ErrNotFound if no default is set.
func (s *pgStore) GetRiskTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error) {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return nil, err
	}

	q := `
		SELECT
			tenant_id, warn_level, block_level, simulation_enabled,
			fail_mode, created_at, updated_at
		FROM risk_tenant_defaults
		WHERE tenant_id = $1
		LIMIT 1
	`

	var defaults RiskTenantDefaults
	row := s.pool.QueryRow(ctx, q, tenantID)
	err := row.Scan(
		&defaults.TenantID, &defaults.WarnLevel, &defaults.BlockLevel,
		&defaults.SimulationEnabled, &defaults.FailMode, &defaults.CreatedAt, &defaults.UpdatedAt,
	)
	if err != nil {
		return nil, mapErr(err)
	}

	return &defaults, nil
}

// UpsertRiskTenantDefaults creates or replaces the default risk policy for a tenant (idempotent).
func (s *pgStore) UpsertRiskTenantDefaults(ctx context.Context, defaults *RiskTenantDefaults) error {
	if err := validateInput(defaults.TenantID, "tenantId"); err != nil {
		return err
	}
	if err := validateRiskLevel(defaults.WarnLevel); err != nil {
		return err
	}
	if err := validateRiskLevel(defaults.BlockLevel); err != nil {
		return err
	}
	if err := validateFailMode(defaults.FailMode); err != nil {
		return err
	}

	q := `
		INSERT INTO risk_tenant_defaults
			(tenant_id, warn_level, block_level, simulation_enabled, fail_mode, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, COALESCE($6, now()), COALESCE($7, now()))
		ON CONFLICT (tenant_id) DO UPDATE SET
			warn_level = EXCLUDED.warn_level,
			block_level = EXCLUDED.block_level,
			simulation_enabled = EXCLUDED.simulation_enabled,
			fail_mode = EXCLUDED.fail_mode,
			updated_at = now()
		RETURNING
			tenant_id, warn_level, block_level, simulation_enabled,
			fail_mode, created_at, updated_at
	`

	row := s.pool.QueryRow(ctx, q,
		defaults.TenantID, defaults.WarnLevel, defaults.BlockLevel,
		defaults.SimulationEnabled, defaults.FailMode, nullableTime(defaults.CreatedAt), nullableTime(defaults.UpdatedAt),
	)

	return mapErr(row.Scan(
		&defaults.TenantID, &defaults.WarnLevel, &defaults.BlockLevel,
		&defaults.SimulationEnabled, &defaults.FailMode, &defaults.CreatedAt, &defaults.UpdatedAt,
	))
}

// DeleteRiskTenantDefaults removes the default for a tenant.
func (s *pgStore) DeleteRiskTenantDefaults(ctx context.Context, tenantID string) error {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return err
	}

	_, err := s.pool.Exec(ctx,
		`DELETE FROM risk_tenant_defaults WHERE tenant_id = $1`,
		tenantID,
	)
	return mapErr(err)
}
