package store

import (
	"context"
	"time"
)

// RiskLevel represents a severity level for risk scoring (from least to most severe).
type RiskLevel string

const (
	RiskLevelNone     RiskLevel = "none"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// RiskAction represents the enforcement action to take when a risk level is reached.
type RiskAction string

const (
	RiskActionAllow RiskAction = "allow"
	RiskActionWarn  RiskAction = "warn"
	RiskActionBlock RiskAction = "block"
)

// FailMode determines how risk evaluation proceeds when upstream services fail.
type FailMode string

const (
	FailModeOpen   FailMode = "open"   // allow on failure (fail-open / optimistic)
	FailModeClosed FailMode = "closed" // block on failure (fail-closed / pessimistic)
)

// =============================================================================
// Risk Configuration Contracts
// =============================================================================

// RiskConfig is the per-dWallet risk policy configuration.
type RiskConfig struct {
	DwalletAddress    string    `json:"dwalletAddress"`
	TenantID          string    `json:"tenantId"`
	WarnLevel         RiskLevel `json:"warnLevel"`  // minimum level to trigger warn action
	BlockLevel        RiskLevel `json:"blockLevel"` // minimum level to trigger block action
	SimulationEnabled bool      `json:"simulationEnabled"`
	FailMode          FailMode  `json:"failMode"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// RiskTenantDefaults is the per-tenant default risk policy (used as fallback for dWallets).
type RiskTenantDefaults struct {
	TenantID          string    `json:"tenantId"`
	WarnLevel         RiskLevel `json:"warnLevel"`
	BlockLevel        RiskLevel `json:"blockLevel"`
	SimulationEnabled bool      `json:"simulationEnabled"`
	FailMode          FailMode  `json:"failMode"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// RiskDenylistEntry is an explicit block entry added by the tenant.
type RiskDenylistEntry struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenantId"`
	Destination string    `json:"destination"`
	Reason      string    `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// RiskAllowlistEntry is an explicit whitelist entry added by the tenant to override false positives.
type RiskAllowlistEntry struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenantId"`
	Destination string    `json:"destination"`
	Reason      string    `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// RiskBlocklistEntry is a globally ingested malicious address.
type RiskBlocklistEntry struct {
	Destination string    `json:"destination"`
	Source      string    `json:"source"`   // feed source name
	Category    string    `json:"category"` // phishing, drainer, malware, etc.
	License     string    `json:"license,omitempty"`
	FetchedAt   time.Time `json:"fetchedAt"`
	ContentHash string    `json:"contentHash,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// DestHistoryEntry tracks a destination address used by a dWallet.
type DestHistoryEntry struct {
	ID             string    `json:"id"`
	DwalletAddress string    `json:"dwalletAddress"`
	Destination    string    `json:"destination"`
	FirstUsedAt    time.Time `json:"firstUsedAt"`
	Count          int64     `json:"count"`
}

// RiskFeedRunState tracks the ingestion state of a blocklist feed.
type RiskFeedRunState struct {
	FeedURL         string     `json:"feedUrl"`
	LastSuccessAt   *time.Time `json:"lastSuccessAt,omitempty"`
	LastErrorAt     *time.Time `json:"lastErrorAt,omitempty"`
	LastErrorMsg    string     `json:"lastErrorMsg,omitempty"`
	EntriesUpserted int        `json:"entriesUpserted"`
	ContentHash     string     `json:"contentHash,omitempty"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// =============================================================================
// Store Interface Contracts (consumed by RT2/RT3)
// =============================================================================

// RiskConfigStore manages per-dWallet risk policies.
type RiskConfigStore interface {
	// GetRiskConfig returns the risk config for a dWallet, or ErrNotFound if none exists.
	GetRiskConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error)

	// UpsertRiskConfig creates or replaces the risk config for a dWallet (idempotent).
	UpsertRiskConfig(ctx context.Context, cfg *RiskConfig) error

	// DeleteRiskConfig removes the risk config for a dWallet.
	DeleteRiskConfig(ctx context.Context, dwalletAddress string) error
}

// RiskTenantDefaultsStore manages per-tenant default risk policies.
type RiskTenantDefaultsStore interface {
	// GetRiskTenantDefaults returns the default risk policy for a tenant, or ErrNotFound if none exists.
	GetRiskTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error)

	// UpsertRiskTenantDefaults creates or replaces the default for a tenant (idempotent).
	UpsertRiskTenantDefaults(ctx context.Context, defaults *RiskTenantDefaults) error

	// DeleteRiskTenantDefaults removes the default for a tenant.
	DeleteRiskTenantDefaults(ctx context.Context, tenantID string) error
}

// RiskDenylistStore manages tenant-scoped denylists.
type RiskDenylistStore interface {
	// AddToDenylist adds a destination to the tenant's denylist (idempotent).
	AddToDenylist(ctx context.Context, tenantID, destination, reason string) (*RiskDenylistEntry, error)

	// RemoveFromDenylist removes a destination from the tenant's denylist.
	RemoveFromDenylist(ctx context.Context, tenantID, destination string) error

	// GetDenylistEntry checks if a destination is in the tenant's denylist.
	// Returns (nil, nil) if not found — absence is the common case and not an error.
	GetDenylistEntry(ctx context.Context, tenantID, destination string) (*RiskDenylistEntry, error)

	// ListDenylistByTenant returns denylist entries for a tenant (capped at 500).
	ListDenylistByTenant(ctx context.Context, tenantID string, limit int) ([]*RiskDenylistEntry, error)
}

// RiskAllowlistStore manages tenant-scoped allowlists.
type RiskAllowlistStore interface {
	// AddToAllowlist adds a destination to the tenant's allowlist (idempotent).
	AddToAllowlist(ctx context.Context, tenantID, destination, reason string) (*RiskAllowlistEntry, error)

	// RemoveFromAllowlist removes a destination from the tenant's allowlist.
	RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error

	// GetAllowlistEntry checks if a destination is in the tenant's allowlist.
	// Returns (nil, nil) if not found — absence is the common case and not an error.
	GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*RiskAllowlistEntry, error)

	// ListAllowlistByTenant returns allowlist entries for a tenant (capped at 500).
	ListAllowlistByTenant(ctx context.Context, tenantID string, limit int) ([]*RiskAllowlistEntry, error)
}

// RiskBlocklistStore manages the global blocklist (ingested from feeds).
type RiskBlocklistStore interface {
	// GetBlocklistEntry checks if a destination is in the global blocklist.
	// Returns (nil, nil) if not found — absence is the common case and not an error.
	GetBlocklistEntry(ctx context.Context, destination string) (*RiskBlocklistEntry, error)

	// UpsertBlocklistEntry adds or updates a blocklist entry (idempotent on destination).
	UpsertBlocklistEntry(ctx context.Context, entry *RiskBlocklistEntry) error

	// DeleteBlocklistEntry removes an entry from the blocklist.
	DeleteBlocklistEntry(ctx context.Context, destination string) error

	// ListBlocklistBySource returns blocklist entries from a source (capped at 500).
	ListBlocklistBySource(ctx context.Context, source string, limit int) ([]*RiskBlocklistEntry, error)

	// DeleteBlocklistBySource removes all entries from a specific source (for refresh).
	DeleteBlocklistBySource(ctx context.Context, source string) error
}

// DestHistoryStore manages per-dWallet destination usage history.
type DestHistoryStore interface {
	// GetDestHistoryEntry returns the history record for a dWallet→destination pair.
	// Returns (nil, nil) if not found — absence is the common case and not an error.
	GetDestHistoryEntry(ctx context.Context, dwalletAddress, destination string) (*DestHistoryEntry, error)

	// RecordDestinationUsage adds or increments the history entry for a destination used by a dWallet.
	RecordDestinationUsage(ctx context.Context, dwalletAddress, destination string) error

	// ListDestHistoryByDwallet returns destination history entries for a dWallet (capped at 500).
	ListDestHistoryByDwallet(ctx context.Context, dwalletAddress string, limit int) ([]*DestHistoryEntry, error)
}

// FeedRunLease represents a claimed feed run lease for horizontal scaling (SELECT FOR UPDATE SKIP LOCKED).
type FeedRunLease struct {
	FeedURL  string
	LeaseID  string    // unique lease token to prevent concurrent execution
	LeaseExp time.Time // lease expiration time
}

// RiskFeedRunStore manages blocklist feed ingestion state.
type RiskFeedRunStore interface {
	// GetFeedRunState returns the ingestion state for a feed URL.
	// Returns (nil, nil) if not found — absence is the common case and not an error.
	GetFeedRunState(ctx context.Context, feedURL string) (*RiskFeedRunState, error)

	// UpsertFeedRunState updates the ingestion state (success, error, content hash).
	UpsertFeedRunState(ctx context.Context, state *RiskFeedRunState) error

	// ClaimDueFeedRuns claims feed runs that are due (never run or overdue) using
	// SELECT ... FOR UPDATE SKIP LOCKED for horizontal scaling across replicas.
	// Returns up to limit feeds marked as leased until leaseExp, or nil if none due.
	// The caller must call UpsertFeedRunState within the lease window to refresh.
	ClaimDueFeedRuns(ctx context.Context, now time.Time, leaseDuration time.Duration, limit int) ([]*FeedRunLease, error)

	// SeedFeedRuns ensures all configured feeds exist in the database.
	// Called at boot to guarantee ClaimDueFeedRuns has feeds to work with.
	// Idempotent: existing feeds are not modified.
	SeedFeedRuns(ctx context.Context, feedURLs []string) error
}
