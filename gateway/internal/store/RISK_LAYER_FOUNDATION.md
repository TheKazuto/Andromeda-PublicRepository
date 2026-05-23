# Risk Layer Foundation (F-RISK-0)

## Overview

This document describes the foundation layer of the off-chain risk scoring system (F-RISK-0). The migration, store repositories, and configuration schema provide the data model and persistence layer for risk evaluation gates that will run in the gateway before signing.

## Address Normalization

All addresses (dWallet addresses, destinations) are stored and looked up in **lowercase hex format without the `0x` prefix**.

### Normalization Function

`normalizeAddress(addr string) string` (in `risk_helpers.go`):
- Removes leading/trailing whitespace
- Strips `0x` or `0X` prefix if present
- Converts to lowercase
- Example: `0xAbCd...` → `abcd...`

**IMPORTANT:** Always normalize addresses before:
- Reading/writing to any risk table
- Comparing addresses in application logic
- Building queries with address parameters

## Database Schema (migration 032_risk_layer.sql)

### Tables

#### `risk_config` (per-dWallet)
- `dwallet_address` (PK) — destination address, normalized
- `tenant_id` (FK) — owning tenant
- `warn_level`, `block_level` — risk levels (none/low/medium/high/critical)
- `simulation_enabled` — boolean flag
- `fail_mode` — open/closed
- `created_at`, `updated_at`
- Index: `tenant_id`

#### `risk_tenant_defaults` (per-tenant)
- `tenant_id` (PK) — owning tenant
- Same policy fields as `risk_config`
- Fallback when no explicit dWallet config exists

#### `risk_denylist` (per-tenant)
- `id`, `tenant_id`, `destination`, `reason`, `created_at`
- Unique index: `(tenant_id, destination)`
- Explicit block list for the tenant

#### `risk_allowlist` (per-tenant)
- `id`, `tenant_id`, `destination`, `reason`, `created_at`
- Unique index: `(tenant_id, destination)`
- Explicit allowlist to override false positives

#### `risk_blocklist` (global)
- `destination` (PK) — normalized address
- `source` — feed source name
- `category` — e.g., "phishing", "drainer", "malware"
- `license`, `fetched_at`, `content_hash` — audit trail
- `created_at`, `updated_at`
- Index: `category`

#### `dest_history` (per-dWallet)
- `id`, `dwallet_address`, `destination`, `first_used_at`, `count`
- Unique index: `(dwallet_address, destination)`
- Tracks first usage timestamp and visit count

#### `risk_feed_runs` (ingestion state)
- `feed_url` (PK) — feed source URL
- `last_success_at`, `last_error_at`, `last_error_msg`
- `entries_upserted` — count from last fetch
- `content_hash` — for dedup across replicas
- `updated_at`

### Request Cost Seeds

8 new route costs are seeded in migration 032:
- `gateway.risk.get-config` (1 token)
- `gateway.risk.put-config` (2 tokens)
- `gateway.risk.get-defaults` (1 token)
- `gateway.risk.put-defaults` (2 tokens)
- `gateway.risk.post-denylist` (2 tokens)
- `gateway.risk.delete-denylist` (2 tokens)
- `gateway.risk.post-allowlist` (2 tokens)
- `gateway.risk.delete-allowlist` (2 tokens)

## Store Interface Contracts (for RT2/RT3)

All store methods are receivers on `pgStore` (which satisfies the interfaces defined in `risk_contracts.go`).

### RiskConfigStore

```go
GetRiskConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error)
UpsertRiskConfig(ctx context.Context, cfg *RiskConfig) error
DeleteRiskConfig(ctx context.Context, dwalletAddress string) error
```

- Operates on per-dWallet risk policies
- `UpsertRiskConfig` is idempotent (INSERT ... ON CONFLICT)
- Returns `ErrNotFound` if config does not exist (via `mapErr`)

### RiskTenantDefaultsStore

```go
GetRiskTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error)
UpsertRiskTenantDefaults(ctx context.Context, defaults *RiskTenantDefaults) error
DeleteRiskTenantDefaults(ctx context.Context, tenantID string) error
```

- Manages per-tenant default policies
- Idempotent upsert
- Fallback when no explicit dWallet config exists

### RiskDenylistStore

```go
AddToDenylist(ctx context.Context, tenantID, destination, reason string) (*RiskDenylistEntry, error)
RemoveFromDenylist(ctx context.Context, tenantID, destination string) error
GetDenylistEntry(ctx context.Context, tenantID, destination string) (*RiskDenylistEntry, error)
ListDenylistByTenant(ctx context.Context, tenantID string) ([]*RiskDenylistEntry, error)
```

- Tenant-scoped explicit blocks
- Idempotent add
- Addresses must be normalized

### RiskAllowlistStore

```go
AddToAllowlist(ctx context.Context, tenantID, destination, reason string) (*RiskAllowlistEntry, error)
RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error
GetAllowlistEntry(ctx context.Context, tenantID, destination string) (*RiskAllowlistEntry, error)
ListAllowlistByTenant(ctx context.Context, tenantID string) ([]*RiskAllowlistEntry, error)
```

- Tenant-scoped allowlist (for false-positive override)
- Idempotent add
- Addresses must be normalized

### RiskBlocklistStore

```go
GetBlocklistEntry(ctx context.Context, destination string) (*RiskBlocklistEntry, error)
UpsertBlocklistEntry(ctx context.Context, entry *RiskBlocklistEntry) error
DeleteBlocklistEntry(ctx context.Context, destination string) error
ListBlocklistBySource(ctx context.Context, source string) ([]*RiskBlocklistEntry, error)
DeleteBlocklistBySource(ctx context.Context, source string) error
```

- Global blocklist (ingested from feeds)
- Idempotent upsert
- `DeleteBlocklistBySource` used for feed refresh

### DestHistoryStore

```go
GetDestHistoryEntry(ctx context.Context, dwalletAddress, destination string) (*DestHistoryEntry, error)
RecordDestinationUsage(ctx context.Context, dwalletAddress, destination string) error
ListDestHistoryByDwallet(ctx context.Context, dwalletAddress string) ([]*DestHistoryEntry, error)
```

- Per-dWallet destination usage tracking
- `RecordDestinationUsage` increments count on each call (idempotent)
- Used to detect "first time to this address" signal

### RiskFeedRunStore

```go
GetFeedRunState(ctx context.Context, feedURL string) (*RiskFeedRunState, error)
UpsertFeedRunState(ctx context.Context, state *RiskFeedRunState) error
```

- Tracks blocklist feed ingestion state
- Prevents duplicate processing across replicas
- Used by the ingest job (F-RISK-2)

## Type Definitions (in risk_contracts.go)

### Risk Levels

```go
type RiskLevel string
const (
    RiskLevelNone     RiskLevel = "none"
    RiskLevelLow      RiskLevel = "low"
    RiskLevelMedium   RiskLevel = "medium"
    RiskLevelHigh     RiskLevel = "high"
    RiskLevelCritical RiskLevel = "critical"
)
```

### Risk Actions

```go
type RiskAction string
const (
    RiskActionAllow RiskAction = "allow"
    RiskActionWarn  RiskAction = "warn"
    RiskActionBlock RiskAction = "block"
)
```

### Fail Modes

```go
type FailMode string
const (
    FailModeOpen   FailMode = "open"   // allow on failure
    FailModeClosed FailMode = "closed" // block on failure
)
```

## Validation

### Input Validation

- `validateInput(value, fieldName string) error` — ensures non-empty fields
- `validateRiskLevel(level RiskLevel) error` — validates risk level enum
- `validateFailMode(mode FailMode) error` — validates fail mode enum

All CRUD methods validate their inputs before querying the database.

### Error Handling

- Database "no rows" errors are mapped to `ErrNotFound` via `mapErr()`
- Duplicate key violations on inserts are handled by the migration (ON CONFLICT)
- All errors are returned explicitly; no silent failures

## Configuration (gateway/internal/config/config.go)

New environment variables for risk layer:

| Env Var | Type | Default | Purpose |
|---------|------|---------|---------|
| `RISK_ENABLED` | bool | false | Master gate for risk evaluation |
| `RISK_BLOCKLIST_FEEDS` | CSV | "" | Comma-separated feed URLs to ingest |
| `RISK_INGEST_TICK_SECONDS` | int | 3600 | Frequency of blocklist ingest job |
| `RISK_DEFAULT_WARN_LEVEL` | string | "high" | Default warn threshold for tenants |
| `RISK_DEFAULT_BLOCK_LEVEL` | string | "critical" | Default block threshold for tenants |
| `RISK_FAIL_MODE` | string | "open" | Behavior on eval failure (open/closed) |

Config is loaded in `gateway.internal.config.Load()` and available on `*Config`.

EVM simulation does NOT use a server-side RPC env. The destination-chain RPC is
provided per request by the developer (field `rpc_url` on `POST /v1/policy/risk/evaluate`),
forwarded to the ika-backend, and validated there against SSRF before any call.
We don't host RPCs.

## Next Phases

- **F-RISK-1:** Risk scoring of destination (blocklist, denylist, freshness)
- **F-RISK-2:** Blocklist ingest job (padrão `futuresign/watcher.go`)
- **F-RISK-3:** Calldata decode + heuristic (ika-backend, depends on Update 2 Part B)
- **F-RISK-4:** Transaction simulation (RPC calls, Solana then EVM)
- **F-RISK-5:** Final aggregation, fail mode, webhooks, docs

## Files

- `migrations/032_risk_layer.sql` — schema
- `risk_contracts.go` — types and interface contracts
- `risk_config.go` — RiskConfigStore implementation
- `risk_tenant_defaults.go` — RiskTenantDefaultsStore implementation
- `risk_denylist.go` — RiskDenylistStore implementation
- `risk_allowlist.go` — RiskAllowlistStore implementation
- `risk_blocklist.go` — RiskBlocklistStore implementation
- `dest_history.go` — DestHistoryStore implementation
- `risk_feed_runs.go` — RiskFeedRunStore implementation
- `risk_helpers.go` — validation and normalization helpers
