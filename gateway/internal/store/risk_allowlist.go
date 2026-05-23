package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// AddToAllowlist adds a destination to the tenant's allowlist (idempotent).
func (s *pgStore) AddToAllowlist(ctx context.Context, tenantID, destination, reason string) (*RiskAllowlistEntry, error) {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return nil, err
	}
	if err := validateInput(destination, "destination"); err != nil {
		return nil, err
	}

	var err error
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return nil, err
	}

	q := `
		INSERT INTO risk_allowlist
			(tenant_id, destination, reason, created_at)
		VALUES
			($1, $2, NULLIF($3, ''), now())
		ON CONFLICT (tenant_id, destination) DO UPDATE SET
			reason = COALESCE(NULLIF($3, ''), risk_allowlist.reason)
		RETURNING
			id, tenant_id, destination, reason, created_at
	`

	var entry RiskAllowlistEntry
	row := s.pool.QueryRow(ctx, q, tenantID, destination, reason)
	err = row.Scan(&entry.ID, &entry.TenantID, &entry.Destination, &entry.Reason, &entry.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}

	return &entry, nil
}

// RemoveFromAllowlist removes a destination from the tenant's allowlist.
func (s *pgStore) RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return err
	}
	if err := validateInput(destination, "destination"); err != nil {
		return err
	}

	var err error
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx,
		`DELETE FROM risk_allowlist WHERE tenant_id = $1 AND destination = $2`,
		tenantID, destination,
	)
	return mapErr(err)
}

// GetAllowlistEntry checks if a destination is in the tenant's allowlist.
// Returns (nil, nil) if not found â€” absence is the common case and not an error.
func (s *pgStore) GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*RiskAllowlistEntry, error) {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return nil, err
	}
	if err := validateInput(destination, "destination"); err != nil {
		return nil, err
	}

	var err error
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return nil, err
	}

	q := `
		SELECT id, tenant_id, destination, reason, created_at
		FROM risk_allowlist
		WHERE tenant_id = $1 AND destination = $2
		LIMIT 1
	`

	var entry RiskAllowlistEntry
	row := s.pool.QueryRow(ctx, q, tenantID, destination)
	err = row.Scan(&entry.ID, &entry.TenantID, &entry.Destination, &entry.Reason, &entry.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, mapErr(err)
	}

	return &entry, nil
}

// ListAllowlistByTenant returns all allowlist entries for a tenant.
// Accepts optional limit (max 500 for DoS protection); returns up to that many entries.
// Empty result is not an error.
func (s *pgStore) ListAllowlistByTenant(ctx context.Context, tenantID string, limit int) ([]*RiskAllowlistEntry, error) {
	if err := validateInput(tenantID, "tenantId"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	q := `
		SELECT id, tenant_id, destination, reason, created_at
		FROM risk_allowlist
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := s.pool.Query(ctx, q, tenantID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var entries []*RiskAllowlistEntry
	for rows.Next() {
		var entry RiskAllowlistEntry
		if err = rows.Scan(&entry.ID, &entry.TenantID, &entry.Destination, &entry.Reason, &entry.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		entries = append(entries, &entry)
	}

	return entries, mapErr(rows.Err())
}
