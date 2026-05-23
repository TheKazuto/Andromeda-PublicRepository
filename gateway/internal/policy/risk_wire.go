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
// RiskServiceAdapter implements policy.RiskService interface
// =============================================================================

// RiskServiceAdapter wraps risk.Service as a policy.RiskService,
// converting between policy layer (map[string]interface{}) and risk layer (typed structs).
type RiskServiceAdapter struct {
	svc *risk.Service
}

// NewRiskServiceAdapter creates an adapter wrapping a risk.Service.
func NewRiskServiceAdapter(svc *risk.Service) *RiskServiceAdapter {
	return &RiskServiceAdapter{svc: svc}
}

// Evaluate implements policy.RiskService.Evaluate by converting map input → struct,
// calling risk.Service.Evaluate, and converting result back to map.
func (a *RiskServiceAdapter) Evaluate(ctx context.Context, input interface{}) (interface{}, error) {
	evalInput, err := mapToEvaluateInput(input)
	if err != nil {
		return nil, fmt.Errorf("invalid evaluate input: %w", err)
	}

	score, err := a.svc.Evaluate(ctx, evalInput)
	if err != nil {
		return nil, err
	}

	return scoreToMap(score), nil
}

// mapToEvaluateInput converts map[string]interface{} → risk.EvaluateInput.
// Expected keys: tenant_id, dwallet_address, destination, request_id.
// Optional: simulation, calldata_risk (populated by RT5 sources).
func mapToEvaluateInput(input interface{}) (*risk.EvaluateInput, error) {
	m, ok := input.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("input must be map[string]interface{}, got %T", input)
	}

	evalInput := &risk.EvaluateInput{}

	if v, ok := m["tenant_id"].(string); ok {
		evalInput.TenantID = v
	}
	if v, ok := m["dwallet_address"].(string); ok {
		evalInput.DWalletAddress = v
	}
	if v, ok := m["destination"].(string); ok {
		evalInput.Destination = v
	}
	if v, ok := m["request_id"].(string); ok {
		evalInput.RequestID = v
	}

	return evalInput, nil
}

// scoreToMap converts risk.Score → map[string]interface{} for JSON response.
func scoreToMap(score *risk.Score) map[string]interface{} {
	if score == nil {
		return map[string]interface{}{
			"level":   "none",
			"action":  "allow",
			"reasons": []string{},
		}
	}

	return map[string]interface{}{
		"level":   score.Level,
		"action":  score.Action,
		"reasons": score.Reasons,
	}
}

// =============================================================================
// RiskConfigServiceAdapter implements policy.RiskConfigService interface
// =============================================================================

// RiskConfigServiceAdapter wraps risk.ConfigService as a policy.RiskConfigService.
type RiskConfigServiceAdapter struct {
	svc *risk.ConfigService
}

// NewRiskConfigServiceAdapter creates an adapter wrapping a risk.ConfigService.
func NewRiskConfigServiceAdapter(svc *risk.ConfigService) *RiskConfigServiceAdapter {
	return &RiskConfigServiceAdapter{svc: svc}
}

// UpsertDWalletConfig creates or updates dWallet risk configuration.
func (a *RiskConfigServiceAdapter) UpsertDWalletConfig(ctx context.Context, dwalletAddress, tenantID string,
	warnLevel string, simulationEnabled bool) (interface{}, error) {
	cfg, err := a.svc.UpsertDWalletConfig(ctx, dwalletAddress, tenantID, warnLevel, simulationEnabled)
	if err != nil {
		return nil, err
	}
	// Convert to map for interface{} compatibility
	if cfg == nil {
		return nil, nil
	}
	return map[string]interface{}{
		"dWalletAddress":    cfg.DWalletAddress,
		"tenantId":          cfg.TenantID,
		"warnLevel":         cfg.WarnLevel,
		"simulationEnabled": cfg.SimulationEnabled,
	}, nil
}

// GetDWalletConfig retrieves dWallet risk configuration.
func (a *RiskConfigServiceAdapter) GetDWalletConfig(ctx context.Context, dwalletAddress string) (interface{}, error) {
	cfg, err := a.svc.GetDWalletConfig(ctx, dwalletAddress)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return map[string]interface{}{
		"dWalletAddress":    cfg.DWalletAddress,
		"tenantId":          cfg.TenantID,
		"warnLevel":         cfg.WarnLevel,
		"simulationEnabled": cfg.SimulationEnabled,
	}, nil
}

// DeleteDWalletConfig removes dWallet risk configuration.
func (a *RiskConfigServiceAdapter) DeleteDWalletConfig(ctx context.Context, dwalletAddress string) error {
	return a.svc.DeleteDWalletConfig(ctx, dwalletAddress)
}

// UpsertTenantDefaults creates or updates tenant default risk configuration.
func (a *RiskConfigServiceAdapter) UpsertTenantDefaults(ctx context.Context, tenantID string,
	warnLevel string) (interface{}, error) {
	defaults, err := a.svc.UpsertTenantDefaults(ctx, tenantID, warnLevel)
	if err != nil {
		return nil, err
	}
	if defaults == nil {
		return nil, nil
	}
	return map[string]interface{}{
		"tenantId":  defaults.TenantID,
		"warnLevel": defaults.WarnLevel,
	}, nil
}

// GetTenantDefaults retrieves tenant default risk configuration.
func (a *RiskConfigServiceAdapter) GetTenantDefaults(ctx context.Context, tenantID string) (interface{}, error) {
	defaults, err := a.svc.GetTenantDefaults(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if defaults == nil {
		return nil, nil
	}
	return map[string]interface{}{
		"tenantId":  defaults.TenantID,
		"warnLevel": defaults.WarnLevel,
	}, nil
}

// AddToDenylist adds a destination to the tenant's denylist.
func (a *RiskConfigServiceAdapter) AddToDenylist(ctx context.Context, tenantID, destination, reason string) error {
	return a.svc.AddToDenylist(ctx, tenantID, destination, reason)
}

// RemoveFromDenylist removes a destination from the tenant's denylist.
func (a *RiskConfigServiceAdapter) RemoveFromDenylist(ctx context.Context, tenantID, destination string) error {
	return a.svc.RemoveFromDenylist(ctx, tenantID, destination)
}

// AddToAllowlist adds a destination to the tenant's allowlist.
func (a *RiskConfigServiceAdapter) AddToAllowlist(ctx context.Context, tenantID, destination, reason string) error {
	return a.svc.AddToAllowlist(ctx, tenantID, destination, reason)
}

// RemoveFromAllowlist removes a destination from the tenant's allowlist.
func (a *RiskConfigServiceAdapter) RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error {
	return a.svc.RemoveFromAllowlist(ctx, tenantID, destination)
}

// =============================================================================
// Helper functions for wiring in main.go
// =============================================================================

// NewRiskRegistry creates a source registry for risk evaluation.
func NewRiskRegistry() *risk.Registry {
	return risk.NewRegistry()
}

// NewRiskService creates the core risk scoring service.
// enabled: feature flag
// store: configuration store interface
// logger: slog logger
func NewRiskService(store risk.ConfigStore, logger interface{}) *risk.Service {
	// Logger parameter is interface{} because Go doesn't allow slog import in tests easily.
	// In main.go context, it's always *slog.Logger.
	var slogger *slog.Logger
	if l, ok := logger.(*slog.Logger); ok {
		slogger = l
	}
	return risk.NewService(store, slogger)
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
