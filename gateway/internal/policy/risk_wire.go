package policy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shinkalabs/andromeda-gateway/internal/risk"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

// =============================================================================
// StoreAdapter bridges store.Store → risk.ConfigStore and ConfigStoreWrite
// =============================================================================

// StoreAdapter implements risk.ConfigStore and risk.ConfigStoreWrite,
// converting between store layer types and risk layer types.
type StoreAdapter struct {
	store store.Store
}

// NewStoreAdapter creates an adapter wrapping store.Store.
func NewStoreAdapter(s store.Store) *StoreAdapter {
	return &StoreAdapter{store: s}
}

// GetRiskConfig converts store.RiskConfig → risk.RiskConfig.
func (a *StoreAdapter) GetRiskConfig(ctx context.Context, dwalletAddress string) (*risk.RiskConfig, error) {
	storeCfg, err := a.store.GetRiskConfig(ctx, dwalletAddress)
	if err != nil {
		return nil, err
	}
	if storeCfg == nil {
		return nil, nil
	}

	return &risk.RiskConfig{
		DWalletAddress:    storeCfg.DwalletAddress,
		TenantID:          storeCfg.TenantID,
		WarnLevel:         string(storeCfg.WarnLevel),
		SimulationEnabled: storeCfg.SimulationEnabled,
	}, nil
}

// GetRiskTenantDefaults converts store.RiskTenantDefaults → risk.RiskTenantDefaults.
func (a *StoreAdapter) GetRiskTenantDefaults(ctx context.Context, tenantID string) (*risk.RiskTenantDefaults, error) {
	storeDefaults, err := a.store.GetRiskTenantDefaults(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if storeDefaults == nil {
		return nil, nil
	}

	return &risk.RiskTenantDefaults{
		TenantID:  storeDefaults.TenantID,
		WarnLevel: string(storeDefaults.WarnLevel),
	}, nil
}

// UpsertRiskConfig converts risk.RiskConfig → store.RiskConfig and upserts.
func (a *StoreAdapter) UpsertRiskConfig(ctx context.Context, cfg *risk.RiskConfig) error {
	if cfg == nil {
		return fmt.Errorf("cfg required")
	}

	storeCfg := &store.RiskConfig{
		DwalletAddress:    cfg.DWalletAddress,
		TenantID:          cfg.TenantID,
		WarnLevel:         store.RiskLevel(cfg.WarnLevel),
		SimulationEnabled: cfg.SimulationEnabled,
	}

	return a.store.UpsertRiskConfig(ctx, storeCfg)
}

// DeleteRiskConfig deletes a risk config from the store.
func (a *StoreAdapter) DeleteRiskConfig(ctx context.Context, dwalletAddress string) error {
	return a.store.DeleteRiskConfig(ctx, dwalletAddress)
}

// UpsertRiskTenantDefaults converts risk.RiskTenantDefaults → store.RiskTenantDefaults and upserts.
func (a *StoreAdapter) UpsertRiskTenantDefaults(ctx context.Context, defaults *risk.RiskTenantDefaults) error {
	if defaults == nil {
		return fmt.Errorf("defaults required")
	}

	storeDefaults := &store.RiskTenantDefaults{
		TenantID:  defaults.TenantID,
		WarnLevel: store.RiskLevel(defaults.WarnLevel),
	}

	return a.store.UpsertRiskTenantDefaults(ctx, storeDefaults)
}

// DeleteRiskTenantDefaults deletes tenant defaults from the store.
func (a *StoreAdapter) DeleteRiskTenantDefaults(ctx context.Context, tenantID string) error {
	return a.store.DeleteRiskTenantDefaults(ctx, tenantID)
}

// AddToDenylist adds a destination to the tenant's denylist.
func (a *StoreAdapter) AddToDenylist(ctx context.Context, tenantID, destination, reason string) (*risk.RiskDenylistEntry, error) {
	entry, err := a.store.AddToDenylist(ctx, tenantID, destination, reason)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.RiskDenylistEntry{
		ID:          entry.ID,
		TenantID:    entry.TenantID,
		Destination: entry.Destination,
		Reason:      entry.Reason,
	}, nil
}

// RemoveFromDenylist removes a destination from the tenant's denylist.
func (a *StoreAdapter) RemoveFromDenylist(ctx context.Context, tenantID, destination string) error {
	return a.store.RemoveFromDenylist(ctx, tenantID, destination)
}

// GetDenylistEntry checks if a destination is in the tenant's denylist.
func (a *StoreAdapter) GetDenylistEntry(ctx context.Context, tenantID, destination string) (*risk.RiskDenylistEntry, error) {
	entry, err := a.store.GetDenylistEntry(ctx, tenantID, destination)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.RiskDenylistEntry{
		ID:          entry.ID,
		TenantID:    entry.TenantID,
		Destination: entry.Destination,
		Reason:      entry.Reason,
	}, nil
}

// ListDenylistByTenant returns denylist entries for a tenant.
func (a *StoreAdapter) ListDenylistByTenant(ctx context.Context, tenantID string, limit int) ([]*risk.RiskDenylistEntry, error) {
	entries, err := a.store.ListDenylistByTenant(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return []*risk.RiskDenylistEntry{}, nil
	}

	result := make([]*risk.RiskDenylistEntry, len(entries))
	for i, e := range entries {
		result[i] = &risk.RiskDenylistEntry{
			ID:          e.ID,
			TenantID:    e.TenantID,
			Destination: e.Destination,
			Reason:      e.Reason,
		}
	}
	return result, nil
}

// AddToAllowlist adds a destination to the tenant's allowlist.
func (a *StoreAdapter) AddToAllowlist(ctx context.Context, tenantID, destination, reason string) (*risk.RiskAllowlistEntry, error) {
	entry, err := a.store.AddToAllowlist(ctx, tenantID, destination, reason)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.RiskAllowlistEntry{
		ID:          entry.ID,
		TenantID:    entry.TenantID,
		Destination: entry.Destination,
		Reason:      entry.Reason,
	}, nil
}

// RemoveFromAllowlist removes a destination from the tenant's allowlist.
func (a *StoreAdapter) RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error {
	return a.store.RemoveFromAllowlist(ctx, tenantID, destination)
}

// GetAllowlistEntry checks if a destination is in the tenant's allowlist.
func (a *StoreAdapter) GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*risk.RiskAllowlistEntry, error) {
	entry, err := a.store.GetAllowlistEntry(ctx, tenantID, destination)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.RiskAllowlistEntry{
		ID:          entry.ID,
		TenantID:    entry.TenantID,
		Destination: entry.Destination,
		Reason:      entry.Reason,
	}, nil
}

// ListAllowlistByTenant returns allowlist entries for a tenant.
func (a *StoreAdapter) ListAllowlistByTenant(ctx context.Context, tenantID string, limit int) ([]*risk.RiskAllowlistEntry, error) {
	entries, err := a.store.ListAllowlistByTenant(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return []*risk.RiskAllowlistEntry{}, nil
	}

	result := make([]*risk.RiskAllowlistEntry, len(entries))
	for i, e := range entries {
		result[i] = &risk.RiskAllowlistEntry{
			ID:          e.ID,
			TenantID:    e.TenantID,
			Destination: e.Destination,
			Reason:      e.Reason,
		}
	}
	return result, nil
}

// GetBlocklistEntry checks if a destination is in the global blocklist.
func (a *StoreAdapter) GetBlocklistEntry(ctx context.Context, destination string) (*risk.BlocklistEntry, error) {
	entry, err := a.store.GetBlocklistEntry(ctx, destination)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.BlocklistEntry{
		Destination: entry.Destination,
		Source:      entry.Source,
		Category:    entry.Category,
	}, nil
}

// GetDestHistoryEntry retrieves the history record for a dWallet→destination pair.
func (a *StoreAdapter) GetDestHistoryEntry(ctx context.Context, dwalletAddress, destination string) (*risk.DestHistoryEntry, error) {
	entry, err := a.store.GetDestHistoryEntry(ctx, dwalletAddress, destination)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &risk.DestHistoryEntry{
		DWalletAddress: entry.DwalletAddress,
		Destination:    entry.Destination,
		Count:          entry.Count,
	}, nil
}

// =============================================================================
// Helper functions for wiring in main.go
// =============================================================================
//
// *risk.Service and *risk.ConfigService satisfy policy.RiskService and
// policy.RiskConfigService directly (their method sets already use the concrete
// risk types), so no adapter layer is needed — main wires them straight in.

// NewRiskRegistry creates a source registry for risk evaluation.
func NewRiskRegistry() *risk.Registry {
	return risk.NewRegistry()
}

// NewRiskService creates the core risk scoring service.
// store: configuration store interface
// logger: slog logger (nil falls back to slog.Default inside risk.NewService)
func NewRiskService(store risk.ConfigStore, logger *slog.Logger) *risk.Service {
	return risk.NewService(store, logger)
}

// NewRiskConfigService creates the config management service.
func NewRiskConfigService(store risk.ConfigStoreWrite) *risk.ConfigService {
	return risk.NewConfigService(store)
}

// NewBlocklistSource creates a global blocklist source.
func NewBlocklistSource(store risk.BlocklistStore) *risk.BlocklistSource {
	return risk.NewBlocklistSource(store)
}

// NewTenantDenylistSource creates a tenant-scoped denylist source.
func NewTenantDenylistSource(store risk.DenylistStore) *risk.TenantDenylistSource {
	return risk.NewTenantDenylistSource(store)
}

// NewTenantAllowlistSource creates a tenant-scoped allowlist source.
func NewTenantAllowlistSource(store risk.AllowlistStore) *risk.TenantAllowlistSource {
	return risk.NewTenantAllowlistSource(store)
}

// NewDestHistorySource creates a destination history source.
func NewDestHistorySource(store risk.DestHistoryStore) *risk.DestHistorySource {
	return risk.NewDestHistorySource(store)
}
