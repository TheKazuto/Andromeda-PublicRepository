package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/shinkalabs/andromeda-gateway/internal/networks"
)

type Config struct {
	Port     string
	Env      string
	LogLevel string

	DatabaseURL string
	RedisURL    string

	RateLimitFailOpen bool

	// IdempotencyFailClosed makes the idempotency middleware reject with 503
	// (instead of passing through) when Redis is unavailable on a route that
	// REQUIRES an Idempotency-Key (destructive mutating routes). Defaults to
	// true in production, false in dev. The DB token_ledger still catches
	// duplicate charges either way; this just refuses the unprotected window.
	IdempotencyFailClosed bool

	// PresignPrefetchEnabled turns on async presign prefetch on the signing
	// challenge (Update 2 Part A). Default off — pre-alpha's mock signer makes
	// presign instant, so there's no latency to hide yet; flip on at Alpha.
	PresignPrefetchEnabled bool
	// PresignPrefetchTTL bounds the ephemeral (tenant, challenge) presign cache.
	PresignPrefetchTTL time.Duration

	AdminToken string

	IkaUpstreamURL     string
	EncryptUpstreamURL string
	// IntentsUpstreamURL points at the intents-backend (LI.FI swap router).
	// Optional: when empty the intents routes return 502/unconfigured, so the
	// feature rolls out behind config without breaking existing deploys.
	IntentsUpstreamURL string
	// InternalAPIKey is the shared secret the gateway uses when proxying to
	// either engine (sent as X-Api-Key to ika-backend, X-Internal-Key to
	// encrypt-backend). Both engines authenticate against the same value.
	InternalAPIKey  string
	UpstreamTimeout time.Duration

	AllowedOrigins    []string
	TrustedProxyCIDRs []string

	DefaultRequestCost    int
	PricingRefreshSeconds time.Duration

	// AuditSignerKind selects how audit entries are signed:
	//   - "env"   (default) — in-process key from ANDROMEDA_AUDIT_PRIVATE_KEY
	//   - "vault"           — HashiCorp Vault Transit Engine (ed25519)
	// Production deployments must set this to "vault" — see docs/AUDIT_KMS.md.
	AuditSignerKind string

	// AuditPrivateKeyB64 is the base64-encoded ed25519 private key (32-byte
	// seed or 64-byte private key). Only used when AuditSignerKind == "env".
	AuditPrivateKeyB64 string

	// Audit snapshot worker (P2.3 follow-up — DR defence-in-depth).
	// Off by default; opt-in via AUDIT_SNAPSHOT_ENABLED=true. Targets
	// Cloudflare R2 by default but any S3-compatible endpoint works.
	AuditSnapshotEnabled   bool
	AuditSnapshotEndpoint  string
	AuditSnapshotBucket    string
	AuditSnapshotRegion    string
	AuditSnapshotAccessKey string
	AuditSnapshotSecretKey string
	AuditSnapshotPrefix    string

	// Vault Transit Engine config — used only when AuditSignerKind == "vault".
	AuditVaultAddr      string
	AuditVaultToken     string
	AuditVaultKeyName   string
	AuditVaultPubKeyB64 string

	// SolanaRPCURL enables on-chain webhook event listening when set.
	SolanaRPCURL string

	// Policy templates registry: maps template name → deployed program id.
	// Populated from ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON.
	TemplateProgramIDsJSON string
	IkaProgramID           string
	IkaCoordinatorAddress  string
	GasSponsorKeypairJSON  string

	// PolicyEngineProgramID is the on-chain address of the deployed
	// PolicyEngine v3 program (the unified successor to the 8 legacy
	// templates). When empty, every /v1/policy/* mutating route returns
	// 503 from `policy.Service.requireSubmitWiring`.
	// Devnet: ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL (deployed 2026-05-15).
	PolicyEngineProgramID string

	// Pyth adapter (oracle relay). The leader-elected crank refreshes the
	// on-chain FeedCache PDAs. Enabled only when ProgramID + AuthorityKey +
	// SolanaRPCURL are all set. AuthorityKey is a 64-byte solana-keygen JSON
	// array (the adapter `authority` — signs + pays refresh/init txs).
	PythAdapterProgramID    string
	PythAdapterAuthorityKey string
	PythAdapterCluster      string
	PythAdapterTick         time.Duration
	PythAdapterFeedsJSON    string
	PythHermesURL           string
	// PythAdapterCrankEnabled turns the periodic refresh crank on. Default OFF
	// (F7.5): refresh-on-sign + the managed price-trigger monitor keep feeds
	// fresh at signing time, so the continuous crank is retired. The one-shot
	// bootstrap (creating FeedCache PDAs) + admin routes still run regardless.
	PythAdapterCrankEnabled bool
	// OracleMonitorTick is how often the managed price-trigger watcher (F7.5)
	// scans armed triggers and reads Hermes.
	OracleMonitorTick time.Duration

	// Oracle off-chain guards (Update 5 / F3). Defensive, not authoritative —
	// the on-chain adapter remains the source of truth. Both 0 = disabled.
	//   - OracleMaxDeviationBPS: the crank refuses to push a refresh whose new
	//     canonical price deviates more than this (basis points) from the last
	//     pushed value — catches bad prints / manipulated spikes.
	//   - OracleMaxPublishLagSeconds: the crank refuses to push, and the monitor
	//     drops, a price whose publish_time is older than this budget.
	OracleMaxDeviationBPS      int
	OracleMaxPublishLagSeconds int

	// Multi-network scaffolding (Update 5 / F4). Off by default; the request hot
	// path still uses the single-network fields above. When enabled,
	// ANDROMEDA_NETWORKS (CSV of extra network names) plus suffixed env blocks
	// (e.g. SOLANA_RPC_URL_TESTNET) define additional networks.
	MultiNetworkEnabled bool
	DefaultNetwork      string
	ExtraNetworks       []string

	// Base URL for SDK artifacts published by the build-sdk GitHub Action
	// (e.g. https://github.com/shinkalabs/andromeda/releases/download).
	// /v1/policies/{address}/sdk concatenates `<base>/<tag>/<template>-ts-client.tgz`.
	SDKBaseURL    string
	SDKVersionTag string // e.g. "sdk-v0.4.0"; falls back to "sdk-v0.1.0"

	// DashboardBaseURL is the public URL of the customer dashboard. Used
	// when generating shareable links (e.g. gift card redeem URLs). When
	// empty, the gateway returns relative paths and the caller is
	// responsible for prefixing.
	DashboardBaseURL string

	// OAuthBroker — Login Social broker (loginsocial.md §5.4 item 1).
	// Disabled by default; when enabled the gateway mounts the
	// /v1/oauth/{authorize,callback,token-exchange} routes that intermediate
	// Google/Apple OAuth and return short-lived id_tokens to tenant apps.
	OAuthBroker OAuthBrokerConfig

	// Risk scoring layer (F-RISK-0+). Always enabled as advisory (never blocks).
	// RISK_ENABLED env var is deprecated and ignored.
	RiskBlocklistFeeds    []string      // RISK_BLOCKLIST_FEEDS (CSV of feed URLs)
	RiskIngestTickSec     time.Duration // RISK_INGEST_TICK_SECONDS (default 3600)
	RiskDefaultWarnLevel  string        // RISK_DEFAULT_WARN_LEVEL (default "high")
	RiskDefaultBlockLevel string        // RISK_DEFAULT_BLOCK_LEVEL (default "critical")
	RiskFailMode          string        // RISK_FAIL_MODE (default "open")

	// Admin envs (ADMIN_JWT_SECRET, ANDROMEDA_BOOTSTRAP_ADMIN_*) moved
	// to the backend service in M4. Gateway only keeps ADMIN_TOKEN as a
	// shared-secret guard for /metrics. SMTP and Stripe envs likewise
	// live on the backend (M1/M2).

	// Warnings collects non-fatal config advisories produced by validate().
	// The logger does not exist yet when Load() runs, so main() flushes
	// these through slog after the logger is up. validate() itself has no
	// log side effects.
	Warnings []string
}

// OAuthBrokerConfig holds the Login Social OAuth broker settings. See
// loginsocial.md §5.4 item 1 + §6.2: the broker hosts the Andromeda OAuth
// client (one client_id per environment), intermediates the handshake with
// Google/Apple using `scope=openid` only, and returns the resulting id_token
// to the tenant app via Authorization Code + PKCE.
type OAuthBrokerConfig struct {
	// Enabled gates the whole feature. When false the broker routes are
	// not mounted and the gateway boots without checking the rest of this
	// struct.
	Enabled bool

	// BaseURL is the publicly reachable URL of the broker (used to build
	// the OAuth redirect_uri sent to Google/Apple — must match the URI
	// registered in the providers' consoles). Example:
	// https://gateway.andromeda.shinka.dev
	BaseURL string

	// StateHMACSecret signs the short-lived OAuth state cookie. Must be
	// at least 32 bytes (base64 or raw). Rotating this invalidates all
	// in-flight handshakes (the cookie TTL is 10 minutes).
	StateHMACSecret string

	// CodeTTLSeconds is how long a short_code returned to the tenant app
	// is valid for the POST /v1/oauth/token-exchange call. Default 60s.
	// Must be >= 30 and <= 300.
	CodeTTLSeconds int

	// GoogleEnabled toggles the Google provider. When true, the two
	// GoogleClient{ID,Secret} fields are required.
	GoogleEnabled      bool
	GoogleClientID     string
	GoogleClientSecret string

	// AppleEnabled toggles the Apple provider. When true, the Apple
	// service id + signing key fields below are all required.
	AppleEnabled    bool
	AppleServiceID  string // a.k.a. client_id
	AppleTeamID     string // 10-char team identifier from Apple Developer
	AppleKeyID      string // 10-char key identifier from Apple Developer
	ApplePrivateKey string // ES256 PEM (PKCS#8). Used to sign the client_secret JWT.
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		Port:                   getenv("PORT", "8081"),
		Env:                    getenv("ENV", "development"),
		LogLevel:               getenv("LOG_LEVEL", "info"),
		DatabaseURL:            getenv("DATABASE_URL", ""),
		RedisURL:               getenv("REDIS_URL", ""),
		RateLimitFailOpen:      getenvBool("RATE_LIMIT_FAIL_OPEN", true),
		PresignPrefetchEnabled: getenvBool("IKA_PRESIGN_PREFETCH_ENABLED", false),
		PresignPrefetchTTL:     time.Duration(getenvInt("IKA_PRESIGN_PREFETCH_TTL_SECONDS", 120)) * time.Second,
		AdminToken:             getenv("ADMIN_TOKEN", "dev-only-admin-token-change-me"),
		IkaUpstreamURL:         strings.TrimRight(getenv("IKA_UPSTREAM_URL", ""), "/"),
		EncryptUpstreamURL:     strings.TrimRight(getenv("ENCRYPT_UPSTREAM_URL", ""), "/"),
		IntentsUpstreamURL:     strings.TrimRight(getenv("INTENTS_UPSTREAM_URL", ""), "/"),
		InternalAPIKey:         getenv("INTERNAL_API_KEY", ""),
		UpstreamTimeout:        time.Duration(getenvInt("UPSTREAM_TIMEOUT_SECONDS", 30)) * time.Second,
		AllowedOrigins:         splitCSV(getenv("ALLOWED_ORIGINS", "")),
		TrustedProxyCIDRs:      splitCSV(getenv("TRUSTED_PROXY_CIDRS", "")),
		DefaultRequestCost:     getenvInt("DEFAULT_REQUEST_COST", 1),
		PricingRefreshSeconds:  time.Duration(getenvInt("PRICING_REFRESH_SECONDS", 60)) * time.Second,
		AuditSnapshotEnabled:   getenvBool("AUDIT_SNAPSHOT_ENABLED", false),
		AuditSnapshotEndpoint:  strings.TrimRight(getenv("AUDIT_SNAPSHOT_S3_ENDPOINT", ""), "/"),
		AuditSnapshotBucket:    getenv("AUDIT_SNAPSHOT_S3_BUCKET", ""),
		AuditSnapshotRegion:    getenv("AUDIT_SNAPSHOT_S3_REGION", "auto"),
		AuditSnapshotAccessKey: getenv("AUDIT_SNAPSHOT_S3_ACCESS_KEY_ID", ""),
		AuditSnapshotSecretKey: getenv("AUDIT_SNAPSHOT_S3_SECRET_ACCESS_KEY", ""),
		AuditSnapshotPrefix:    getenv("AUDIT_SNAPSHOT_S3_PREFIX", "audit/"),
		AuditSignerKind:        strings.ToLower(getenv("ANDROMEDA_AUDIT_SIGNER", "env")),
		AuditPrivateKeyB64:     getenv("ANDROMEDA_AUDIT_PRIVATE_KEY", ""),
		AuditVaultAddr:         getenv("ANDROMEDA_AUDIT_VAULT_ADDR", ""),
		AuditVaultToken:        getenv("ANDROMEDA_AUDIT_VAULT_TOKEN", ""),
		AuditVaultKeyName:      getenv("ANDROMEDA_AUDIT_VAULT_KEY_NAME", ""),
		AuditVaultPubKeyB64:    getenv("ANDROMEDA_AUDIT_VAULT_PUBKEY_B64", ""),
		SolanaRPCURL:           strings.TrimRight(getenv("SOLANA_RPC_URL", ""), "/"),
		TemplateProgramIDsJSON: getenv("ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON", ""),
		IkaProgramID:           getenv("IKA_PROGRAM_ID", ""),
		IkaCoordinatorAddress:  getenv("IKA_COORDINATOR_ADDRESS", ""),
		GasSponsorKeypairJSON:  getenv("ANDROMEDA_GAS_SPONSOR_KEYPAIR", ""),
		PolicyEngineProgramID:  getenv("ANDROMEDA_POLICY_ENGINE_PROGRAM_ID", ""),

		PythAdapterProgramID:    getenv("PYTH_ADAPTER_PROGRAM_ID", ""),
		PythAdapterAuthorityKey: getenv("PYTH_ADAPTER_AUTHORITY_KEY", ""),
		PythAdapterCluster:      getenv("PYTH_ADAPTER_CLUSTER", "devnet"),
		PythAdapterTick:         time.Duration(getenvInt("PYTH_ADAPTER_TICK_SECONDS", 30)) * time.Second,
		PythAdapterFeedsJSON:    getenv("PYTH_ADAPTER_FEEDS", ""),
		PythHermesURL:           strings.TrimRight(getenv("PYTH_HERMES_URL", "https://hermes.pyth.network"), "/"),
		PythAdapterCrankEnabled: getenvBool("PYTH_ADAPTER_CRANK_ENABLED", false),
		OracleMonitorTick:       time.Duration(getenvInt("ORACLE_MONITOR_TICK_SECONDS", 10)) * time.Second,

		// Oracle off-chain guards (Update 5 / F3). Both 0 = disabled (the
		// on-chain adapter still validates staleness + confidence as backstop).
		OracleMaxDeviationBPS:      getenvInt("ORACLE_MAX_DEVIATION_BPS", 0),
		OracleMaxPublishLagSeconds: getenvInt("ORACLE_MAX_PUBLISH_LAG_SECONDS", 0),

		MultiNetworkEnabled: getenvBool("MULTI_NETWORK_ENABLED", false),
		DefaultNetwork:      getenv("NETWORK_NAME", "devnet"),
		ExtraNetworks:       splitCSV(getenv("ANDROMEDA_NETWORKS", "")),

		SDKBaseURL:       strings.TrimRight(getenv("ANDROMEDA_SDK_BASE_URL", ""), "/"),
		SDKVersionTag:    getenv("ANDROMEDA_SDK_VERSION_TAG", "sdk-v0.1.0"),
		DashboardBaseURL: strings.TrimRight(getenv("ANDROMEDA_DASHBOARD_BASE_URL", ""), "/"),
		OAuthBroker: OAuthBrokerConfig{
			Enabled:            getenvBool("OAUTH_BROKER_ENABLED", false),
			BaseURL:            strings.TrimRight(getenv("OAUTH_BROKER_BASE_URL", ""), "/"),
			StateHMACSecret:    getenv("OAUTH_BROKER_STATE_HMAC_SECRET", ""),
			CodeTTLSeconds:     getenvInt("OAUTH_BROKER_CODE_TTL_SECONDS", 60),
			GoogleEnabled:      getenvBool("OAUTH_BROKER_GOOGLE_ENABLED", false),
			GoogleClientID:     getenv("OAUTH_BROKER_GOOGLE_CLIENT_ID", ""),
			GoogleClientSecret: getenv("OAUTH_BROKER_GOOGLE_CLIENT_SECRET", ""),
			AppleEnabled:       getenvBool("OAUTH_BROKER_APPLE_ENABLED", false),
			AppleServiceID:     getenv("OAUTH_BROKER_APPLE_SERVICE_ID", ""),
			AppleTeamID:        getenv("OAUTH_BROKER_APPLE_TEAM_ID", ""),
			AppleKeyID:         getenv("OAUTH_BROKER_APPLE_KEY_ID", ""),
			ApplePrivateKey:    getenv("OAUTH_BROKER_APPLE_PRIVATE_KEY", ""),
		},

		RiskBlocklistFeeds:    splitCSV(getenv("RISK_BLOCKLIST_FEEDS", "")),
		RiskIngestTickSec:     time.Duration(getenvInt("RISK_INGEST_TICK_SECONDS", 3600)) * time.Second,
		RiskDefaultWarnLevel:  getenv("RISK_DEFAULT_WARN_LEVEL", "high"),
		RiskDefaultBlockLevel: getenv("RISK_DEFAULT_BLOCK_LEVEL", "critical"),
		RiskFailMode:          getenv("RISK_FAIL_MODE", "open"),
	}

	// Default fail-closed in production: a Redis outage on a destructive
	// mutating route then returns 503 rather than silently dropping the
	// idempotency guard. Operators can still override with the env var.
	cfg.IdempotencyFailClosed = getenvBool("IDEMPOTENCY_FAIL_CLOSED", cfg.Env == "production")

	if err := cfg.validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	return cfg
}

// Networks returns the inputs for the network registry (Update 5 / F4): the
// default network built from the single-network fields, plus any extras parsed
// from suffixed env blocks (e.g. SOLANA_RPC_URL_TESTNET) when MultiNetworkEnabled.
func (c *Config) Networks() (networks.Network, []networks.Network) {
	def := networks.Network{
		Name:                  c.DefaultNetwork,
		SolanaRPCURL:          c.SolanaRPCURL,
		IkaUpstreamURL:        c.IkaUpstreamURL,
		EncryptUpstreamURL:    c.EncryptUpstreamURL,
		IkaProgramID:          c.IkaProgramID,
		PolicyEngineProgramID: c.PolicyEngineProgramID,
		GasSponsorKeypairJSON: c.GasSponsorKeypairJSON,
	}
	if !c.MultiNetworkEnabled {
		return def, nil
	}
	var extras []networks.Network
	for _, name := range c.ExtraNetworks {
		suffix := "_" + strings.ToUpper(strings.TrimSpace(name))
		extras = append(extras, networks.Network{
			Name:                  name,
			SolanaRPCURL:          strings.TrimRight(getenv("SOLANA_RPC_URL"+suffix, ""), "/"),
			IkaUpstreamURL:        strings.TrimRight(getenv("IKA_UPSTREAM_URL"+suffix, ""), "/"),
			EncryptUpstreamURL:    strings.TrimRight(getenv("ENCRYPT_UPSTREAM_URL"+suffix, ""), "/"),
			IkaProgramID:          getenv("IKA_PROGRAM_ID"+suffix, ""),
			PolicyEngineProgramID: getenv("ANDROMEDA_POLICY_ENGINE_PROGRAM_ID"+suffix, ""),
			GasSponsorKeypairJSON: getenv("ANDROMEDA_GAS_SPONSOR_KEYPAIR"+suffix, ""),
		})
	}
	return def, extras
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.Env == "production" {
		if c.AdminToken == "dev-only-admin-token-change-me" || len(c.AdminToken) < 32 {
			return fmt.Errorf("ADMIN_TOKEN must be set to a strong value in production")
		}
		if c.InternalAPIKey == "" {
			return fmt.Errorf("INTERNAL_API_KEY is required in production (shared with ika-backend and encrypt-backend)")
		}
		if c.IkaUpstreamURL == "" {
			return fmt.Errorf("IKA_UPSTREAM_URL is required in production")
		}
		if c.EncryptUpstreamURL == "" {
			return fmt.Errorf("ENCRYPT_UPSTREAM_URL is required in production")
		}
		// Rate limit + idempotency are no-ops without Redis. Allowing a prod
		// deploy to boot without it would silently disable both — refuse.
		if c.RedisURL == "" {
			return fmt.Errorf("REDIS_URL is required in production (backs rate limiting and idempotency)")
		}
		// Fail-open in production means: Redis down ⇒ unlimited traffic. The
		// correct posture is fail-closed (return 503). Force operators to be
		// explicit rather than override silently.
		if c.RateLimitFailOpen {
			return fmt.Errorf("RATE_LIMIT_FAIL_OPEN must be false in production — when Redis is unavailable the gateway must reject with 503, not serve unthrottled")
		}
		// P2.1: an empty ALLOWED_ORIGINS in production silently disables
		// CORS (the cors middleware no-ops). The dashboard would still
		// work because credentialed XHR doesn't need wildcard, but ANY
		// third-party site could exfil JSON via fetch(). Force operators
		// to list the dashboard origin explicitly.
		if len(c.AllowedOrigins) == 0 {
			return fmt.Errorf("ALLOWED_ORIGINS is required in production (comma-separated dashboard origins, e.g. https://app.andromedainfra.pro)")
		}
		for _, o := range c.AllowedOrigins {
			if o == "*" {
				return fmt.Errorf("ALLOWED_ORIGINS=* is not allowed in production — list each dashboard origin explicitly")
			}
		}
	}
	if c.DefaultRequestCost < 1 {
		return fmt.Errorf("DEFAULT_REQUEST_COST must be >= 1")
	}
	// Validate proxy CIDRs: a malformed entry is fatal in production (the IP
	// allowlist depends on these) but only a warning in dev.
	for _, raw := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			if c.Env == "production" {
				return fmt.Errorf("TRUSTED_PROXY_CIDRS contains an invalid CIDR %q: %w", raw, err)
			}
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR — ignored", raw))
		}
	}
	switch c.AuditSignerKind {
	case "env", "":
		c.AuditSignerKind = "env"
	case "vault":
		if c.AuditVaultAddr == "" || c.AuditVaultToken == "" ||
			c.AuditVaultKeyName == "" || c.AuditVaultPubKeyB64 == "" {
			return fmt.Errorf("ANDROMEDA_AUDIT_SIGNER=vault requires ANDROMEDA_AUDIT_VAULT_{ADDR,TOKEN,KEY_NAME,PUBKEY_B64}")
		}
	default:
		return fmt.Errorf("ANDROMEDA_AUDIT_SIGNER must be 'env' or 'vault', got %q", c.AuditSignerKind)
	}
	if c.Env == "production" && c.AuditSignerKind == "env" {
		// Don't refuse to boot — env signing still works. Surface a loud
		// advisory so operators migrate to Vault. See docs/AUDIT_KMS.md.
		c.Warnings = append(c.Warnings,
			"ANDROMEDA_AUDIT_SIGNER=env in production — migrate to 'vault' (see docs/AUDIT_KMS.md)")
	}
	if err := c.validateOAuthBroker(); err != nil {
		return err
	}
	if err := c.validateRiskLayer(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateOAuthBroker() error {
	b := &c.OAuthBroker
	if !b.Enabled {
		return nil
	}
	if b.BaseURL == "" {
		return fmt.Errorf("OAUTH_BROKER_BASE_URL is required when OAUTH_BROKER_ENABLED=true")
	}
	if !strings.HasPrefix(b.BaseURL, "https://") && c.Env == "production" {
		return fmt.Errorf("OAUTH_BROKER_BASE_URL must be https:// in production (got %q)", b.BaseURL)
	}
	if len(b.StateHMACSecret) < 32 {
		return fmt.Errorf("OAUTH_BROKER_STATE_HMAC_SECRET must be at least 32 bytes when OAUTH_BROKER_ENABLED=true")
	}
	if b.CodeTTLSeconds < 30 || b.CodeTTLSeconds > 300 {
		return fmt.Errorf("OAUTH_BROKER_CODE_TTL_SECONDS must be in [30, 300] (got %d)", b.CodeTTLSeconds)
	}
	if !b.GoogleEnabled && !b.AppleEnabled {
		return fmt.Errorf("OAUTH_BROKER_ENABLED=true requires at least one provider (OAUTH_BROKER_GOOGLE_ENABLED or OAUTH_BROKER_APPLE_ENABLED)")
	}
	if b.GoogleEnabled {
		if b.GoogleClientID == "" || b.GoogleClientSecret == "" {
			return fmt.Errorf("OAUTH_BROKER_GOOGLE_ENABLED=true requires OAUTH_BROKER_GOOGLE_CLIENT_ID and OAUTH_BROKER_GOOGLE_CLIENT_SECRET")
		}
	}
	if b.AppleEnabled {
		if b.AppleServiceID == "" || b.AppleTeamID == "" || b.AppleKeyID == "" || b.ApplePrivateKey == "" {
			return fmt.Errorf("OAUTH_BROKER_APPLE_ENABLED=true requires OAUTH_BROKER_APPLE_{SERVICE_ID,TEAM_ID,KEY_ID,PRIVATE_KEY}")
		}
		if len(b.AppleTeamID) != 10 || len(b.AppleKeyID) != 10 {
			c.Warnings = append(c.Warnings,
				"OAUTH_BROKER_APPLE_{TEAM_ID,KEY_ID} are typically 10 characters — double-check the values")
		}
	}
	if c.RedisURL == "" {
		return fmt.Errorf("OAUTH_BROKER_ENABLED=true requires REDIS_URL (the short-lived code↔id_token store needs Redis)")
	}
	return nil
}

func (c *Config) validateRiskLayer() error {
	// Risk layer is always available (advisory-only); validate configuration
	// parameters if they are non-empty.

	// Validate RISK_FAIL_MODE if non-empty
	if c.RiskFailMode != "" {
		switch c.RiskFailMode {
		case "open", "closed":
			// Valid
		default:
			return fmt.Errorf("RISK_FAIL_MODE must be 'open' or 'closed' (got %q)", c.RiskFailMode)
		}
	}

	// Validate RISK_DEFAULT_WARN_LEVEL if non-empty
	validRiskLevel := map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
	if c.RiskDefaultWarnLevel != "" && !validRiskLevel[c.RiskDefaultWarnLevel] {
		return fmt.Errorf("RISK_DEFAULT_WARN_LEVEL must be one of: none, low, medium, high, critical (got %q)", c.RiskDefaultWarnLevel)
	}

	// Validate RISK_DEFAULT_BLOCK_LEVEL if non-empty
	if c.RiskDefaultBlockLevel != "" && !validRiskLevel[c.RiskDefaultBlockLevel] {
		return fmt.Errorf("RISK_DEFAULT_BLOCK_LEVEL must be one of: none, low, medium, high, critical (got %q)", c.RiskDefaultBlockLevel)
	}

	// Validate RISK_INGEST_TICK_SECONDS is positive if set
	if c.RiskIngestTickSec <= 0 {
		return fmt.Errorf("RISK_INGEST_TICK_SECONDS must be positive (got %v)", c.RiskIngestTickSec)
	}

	return nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
