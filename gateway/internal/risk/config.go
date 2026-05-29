package risk

import (
	"context"
	"time"
)

// ConfigService handles the persistence and retrieval of risk configuration
// for dWallets and tenants. It wraps the store and provides validation.
type ConfigService struct {
	store ConfigStoreWrite
}

// NewConfigService creates a config service wrapping the store.
func NewConfigService(store ConfigStoreWrite) *ConfigService {
	return &ConfigService{store: store}
}

// UpsertDWalletConfig creates or updates the risk configuration for a dWallet.
// Risk Layer is purely advisory (never blocks), so only warn_level is configurable.
func (cs *ConfigService) UpsertDWalletConfig(ctx context.Context, dwalletAddress, tenantID string,
	warnLevel string, simulationEnabled bool) (*RiskConfig, error) {

	cfg := &RiskConfig{
		DWalletAddress:    dwalletAddress,
		TenantID:          tenantID,
		WarnLevel:         warnLevel,
		SimulationEnabled: simulationEnabled,
	}

	if err := cs.store.UpsertRiskConfig(ctx, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// GetDWalletConfig retrieves the risk config for a dWallet.
func (cs *ConfigService) GetDWalletConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error) {
	return cs.store.GetRiskConfig(ctx, dwalletAddress)
}

// DeleteDWalletConfig removes the risk config for a dWallet, scoped to the
// owning tenant (deny-by-default: a cross-tenant delete is a no-op).
func (cs *ConfigService) DeleteDWalletConfig(ctx context.Context, dwalletAddress, tenantID string) error {
	return cs.store.DeleteRiskConfig(ctx, dwalletAddress, tenantID)
}

// UpsertTenantDefaults creates or updates the default risk policy for a tenant.
// Risk Layer is purely advisory, so only warn_level is configurable.
func (cs *ConfigService) UpsertTenantDefaults(ctx context.Context, tenantID string,
	warnLevel string) (*RiskTenantDefaults, error) {

	defaults := &RiskTenantDefaults{
		TenantID:  tenantID,
		WarnLevel: warnLevel,
	}

	if err := cs.store.UpsertRiskTenantDefaults(ctx, defaults); err != nil {
		return nil, err
	}

	return defaults, nil
}

// GetTenantDefaults retrieves the default risk policy for a tenant.
func (cs *ConfigService) GetTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error) {
	return cs.store.GetRiskTenantDefaults(ctx, tenantID)
}

// AddToDenylist adds a destination to a tenant's denylist.
func (cs *ConfigService) AddToDenylist(ctx context.Context, tenantID, destination, reason string) error {
	// This is a simple write; the store handles validation/idempotency.
	// In a real system, you'd validate the destination format here.
	_, err := cs.store.AddToDenylist(ctx, tenantID, destination, reason)
	return err
}

// RemoveFromDenylist removes a destination from a tenant's denylist.
func (cs *ConfigService) RemoveFromDenylist(ctx context.Context, tenantID, destination string) error {
	return cs.store.RemoveFromDenylist(ctx, tenantID, destination)
}

// AddToAllowlist adds a destination to a tenant's allowlist.
func (cs *ConfigService) AddToAllowlist(ctx context.Context, tenantID, destination, reason string) error {
	_, err := cs.store.AddToAllowlist(ctx, tenantID, destination, reason)
	return err
}

// RemoveFromAllowlist removes a destination from a tenant's allowlist.
func (cs *ConfigService) RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error {
	return cs.store.RemoveFromAllowlist(ctx, tenantID, destination)
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interface contracts (consumed by ConfigService)
// ─────────────────────────────────────────────────────────────────────────────

// ConfigStoreWrite is the full interface expected by ConfigService.
// It combines read + write operations for risk configuration management.
// The concrete implementation is in gateway/internal/store (DB layer).
type ConfigStoreWrite interface {
	// Read operations
	GetRiskConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error)
	GetRiskTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error)

	// Write operations
	UpsertRiskConfig(ctx context.Context, cfg *RiskConfig) error
	DeleteRiskConfig(ctx context.Context, dwalletAddress, tenantID string) error

	UpsertRiskTenantDefaults(ctx context.Context, defaults *RiskTenantDefaults) error
	DeleteRiskTenantDefaults(ctx context.Context, tenantID string) error

	AddToDenylist(ctx context.Context, tenantID, destination, reason string) (*RiskDenylistEntry, error)
	RemoveFromDenylist(ctx context.Context, tenantID, destination string) error
	GetDenylistEntry(ctx context.Context, tenantID, destination string) (*RiskDenylistEntry, error)
	ListDenylistByTenant(ctx context.Context, tenantID string, limit int) ([]*RiskDenylistEntry, error)

	AddToAllowlist(ctx context.Context, tenantID, destination, reason string) (*RiskAllowlistEntry, error)
	RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error
	GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*RiskAllowlistEntry, error)
	ListAllowlistByTenant(ctx context.Context, tenantID string, limit int) ([]*RiskAllowlistEntry, error)
}

// RiskDenylistEntry represents a tenant-scoped denylist entry.
type RiskDenylistEntry struct {
	ID          string
	TenantID    string
	Destination string
	Reason      string
	CreatedAt   time.Time
}

// RiskAllowlistEntry represents a tenant-scoped allowlist entry.
type RiskAllowlistEntry struct {
	ID          string
	TenantID    string
	Destination string
	Reason      string
	CreatedAt   time.Time
}
