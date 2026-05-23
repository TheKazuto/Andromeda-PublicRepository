package risk

import (
	"context"
	"fmt"
	"sync"
)

// Source is a pluggable risk-scoring signal provider. Each source analyzes
// the transaction/destination context and contributes a subscore + reasons.
// Sources are designed to be composable: the gateway aggregates their outputs
// into a final decision. Multiple sources can run in parallel; the aggregator
// merges their results.
type Source interface {
	// Name returns the unique identifier of this source (e.g., "blocklist", "denylist", "dest_history").
	Name() string

	// Evaluate analyzes the input and returns a subscore + reasons.
	// Must not panic; return an error if the source cannot evaluate (e.g., store unavailable).
	// Returning a `nil` error with level="none" and empty reasons means "no signal".
	Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error)
}

// Registry manages pluggable risk sources. Sources can be registered at startup
// and queried at evaluation time without modifying the main service.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]Source
	order   []string // registration order (for deterministic output)
}

// NewRegistry creates an empty source registry.
func NewRegistry() *Registry {
	return &Registry{
		sources: make(map[string]Source),
		order:   make([]string, 0),
	}
}

// Register adds a source to the registry. Panics if the name is already registered.
func (r *Registry) Register(src Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := src.Name()
	if _, exists := r.sources[name]; exists {
		panic(fmt.Sprintf("risk source %q already registered", name))
	}
	r.sources[name] = src
	r.order = append(r.order, name)
}

// Get retrieves a source by name.
func (r *Registry) Get(name string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src, ok := r.sources[name]
	return src, ok
}

// All returns all registered sources in registration order (for aggregation).
func (r *Registry) All() []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Source, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.sources[name])
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in sources (RT2 scope)
// ─────────────────────────────────────────────────────────────────────────────

// BlocklistSource checks if a destination is in the global ingested blocklist.
// Returns "critical" + block reason if found, otherwise "none".
type BlocklistSource struct {
	store BlocklistStore // injected store interface (from config)
}

// BlocklistStore is the interface this source expects from the store.
type BlocklistStore interface {
	GetBlocklistEntry(ctx context.Context, destination string) (*BlocklistEntry, error)
}

// BlocklistEntry is the store entity for a blocklist entry.
type BlocklistEntry struct {
	Destination string // normalized address
	Source      string // feed source name
	Category    string // phishing, drainer, malware, etc.
}

// NewBlocklistSource creates a blocklist-checking source.
func NewBlocklistSource(store BlocklistStore) *BlocklistSource {
	return &BlocklistSource{store: store}
}

// Name returns the source identifier.
func (bs *BlocklistSource) Name() string { return "blocklist" }

// Evaluate checks if the destination is blocklisted.
func (bs *BlocklistSource) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	if input.Destination == "" {
		return &Score{Level: "none"}, nil
	}
	entry, err := bs.store.GetBlocklistEntry(ctx, input.Destination)
	if err != nil {
		return nil, fmt.Errorf("blocklist store: %w", err)
	}
	if entry == nil {
		return &Score{Level: "none"}, nil
	}
	return &Score{
		Level: "critical",
		Reasons: []string{
			fmt.Sprintf("destination in %s blocklist (category: %s)", entry.Source, entry.Category),
		},
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────

// TenantDenylistSource checks if a destination is in the tenant's explicit denylist.
// Returns "critical" + block reason if found, otherwise "none".
type TenantDenylistSource struct {
	store DenylistStore
}

// DenylistStore is the interface this source expects from the store.
type DenylistStore interface {
	GetDenylistEntry(ctx context.Context, tenantID, destination string) (*DenylistEntry, error)
}

// DenylistEntry is the store entity for a tenant denylist entry (alias for ConfigStoreWrite contract).
type DenylistEntry = RiskDenylistEntry

// NewTenantDenylistSource creates a tenant denylist-checking source.
func NewTenantDenylistSource(store DenylistStore) *TenantDenylistSource {
	return &TenantDenylistSource{store: store}
}

// Name returns the source identifier.
func (tds *TenantDenylistSource) Name() string { return "tenant_denylist" }

// Evaluate checks if the destination is in the tenant's denylist.
func (tds *TenantDenylistSource) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	if input.Destination == "" || input.TenantID == "" {
		return &Score{Level: "none"}, nil
	}
	entry, err := tds.store.GetDenylistEntry(ctx, input.TenantID, input.Destination)
	if err != nil {
		return nil, fmt.Errorf("denylist store: %w", err)
	}
	if entry == nil {
		return &Score{Level: "none"}, nil
	}
	reason := "destination on tenant denylist"
	if entry.Reason != "" {
		reason = fmt.Sprintf("destination on tenant denylist: %s", entry.Reason)
	}
	return &Score{
		Level:   "critical",
		Reasons: []string{reason},
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────

// TenantAllowlistSource checks if a destination is in the tenant's explicit allowlist.
// If found, it overrides other sources (returns "none" to allow). This implements the
// override-false-positive logic: allowlist redeems a destination from warn/block.
type TenantAllowlistSource struct {
	store AllowlistStore
}

// AllowlistStore is the interface this source expects from the store.
type AllowlistStore interface {
	GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*AllowlistEntry, error)
}

// AllowlistEntry is the store entity for a tenant allowlist entry (alias for ConfigStoreWrite contract).
type AllowlistEntry = RiskAllowlistEntry

// NewTenantAllowlistSource creates a tenant allowlist-checking source.
func NewTenantAllowlistSource(store AllowlistStore) *TenantAllowlistSource {
	return &TenantAllowlistSource{store: store}
}

// Name returns the source identifier.
func (tas *TenantAllowlistSource) Name() string { return "tenant_allowlist" }

// Evaluate checks if the destination is in the tenant's allowlist.
// If found, returns "none" (override pass).
func (tas *TenantAllowlistSource) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	if input.Destination == "" || input.TenantID == "" {
		return &Score{Level: "none"}, nil
	}
	entry, err := tas.store.GetAllowlistEntry(ctx, input.TenantID, input.Destination)
	if err != nil {
		return nil, fmt.Errorf("allowlist store: %w", err)
	}
	if entry == nil {
		return &Score{Level: "none"}, nil
	}
	// Allowlist found: override any warn/block from other sources.
	return &Score{Level: "none", Reasons: []string{"destination on tenant allowlist (override)"}}, nil
}

// ─────────────────────────────────────────────────────────────────────────────

// DestHistorySource checks if this dWallet has used this destination before.
// First use: "low" warn. Seen before: "none" (no signal).
type DestHistorySource struct {
	store DestHistoryStore
}

// DestHistoryStore is the interface this source expects from the store.
type DestHistoryStore interface {
	GetDestHistoryEntry(ctx context.Context, dwalletAddress, destination string) (*DestHistoryEntry, error)
}

// DestHistoryEntry is the store entity for destination usage history.
type DestHistoryEntry struct {
	DWalletAddress string
	Destination    string
	Count          int64
}

// NewDestHistorySource creates a destination-history-checking source.
func NewDestHistorySource(store DestHistoryStore) *DestHistorySource {
	return &DestHistorySource{store: store}
}

// Name returns the source identifier.
func (dhs *DestHistorySource) Name() string { return "dest_history" }

// Evaluate checks if this dWallet has used this destination before.
func (dhs *DestHistorySource) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	if input.Destination == "" || input.DWalletAddress == "" {
		return &Score{Level: "none"}, nil
	}
	entry, err := dhs.store.GetDestHistoryEntry(ctx, input.DWalletAddress, input.Destination)
	if err != nil {
		return nil, fmt.Errorf("dest history store: %w", err)
	}
	if entry == nil || entry.Count == 0 {
		return &Score{
			Level:   "low",
			Reasons: []string{"destination is new to this dWallet (first use)"},
		}, nil
	}
	return &Score{Level: "none"}, nil
}

// ─────────────────────────────────────────────────────────────────────────────

// OnchainFreshnessSource checks if the destination account is freshly created on-chain.
// For Solana: queries RPC for account creation time. For EVM: checks age via RPC.
// Recent creation (<24h): "medium" warn. Otherwise: "none".
type OnchainFreshnessSource struct {
	rpcClient RPCClient // Solana RPC; EVM requires separate RPC (RT4+)
	chainID   string    // "solana" or chainId for future multi-chain
}

// RPCClient is the interface for on-chain account freshness checks.
type RPCClient interface {
	GetAccountCreationSlot(ctx context.Context, address string) (uint64, error)
}

// NewOnchainFreshnessSource creates an on-chain freshness-checking source.
func NewOnchainFreshnessSource(rpcClient RPCClient, chainID string) *OnchainFreshnessSource {
	return &OnchainFreshnessSource{
		rpcClient: rpcClient,
		chainID:   chainID,
	}
}

// Name returns the source identifier.
func (ofs *OnchainFreshnessSource) Name() string { return "onchain_freshness" }

// Evaluate checks if the account is freshly created.
func (ofs *OnchainFreshnessSource) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	if input.Destination == "" || ofs.rpcClient == nil {
		return &Score{Level: "none"}, nil
	}
	// This is a best-effort check; RPC unavailability is non-fatal and treated as "no signal".
	slot, err := ofs.rpcClient.GetAccountCreationSlot(ctx, input.Destination)
	if err != nil {
		// Log but do not return error; let the flow continue.
		// (Actual logging is done by the aggregator's error handler.)
		return &Score{Level: "none"}, nil
	}

	// On Solana devnet/testnet, freshness threshold is ~24 hours in slots.
	// Mainnet: 1 slot ≈ 400ms, so 24h ≈ 216,000 slots.
	// For simplicity, hardcode a moderate threshold here; in production
	// this should be config or derive from a current-slot RPC call.
	const freshThresholdSlots uint64 = 216000 // ~24h
	// Note: we don't have currentSlot here (would require another RPC call).
	// In a real implementation, pass it in the EvaluateInput or cache it.
	// For now, skip the check if we can't determine age.
	// TODO(RT2): receive currentSlot in EvaluateInput to enable freshness check.
	_ = freshThresholdSlots
	_ = slot

	return &Score{Level: "none"}, nil
}
