package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port     string
	Env      string
	LogLevel string

	DatabaseURL string
	RedisURL    string

	RateLimitFailOpen bool

	AdminToken string

	IkaUpstreamURL     string
	EncryptUpstreamURL string
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

	// Admin envs (ADMIN_JWT_SECRET, ANDROMEDA_BOOTSTRAP_ADMIN_*) moved
	// to the backend service in M4. Gateway only keeps ADMIN_TOKEN as a
	// shared-secret guard for /metrics. SMTP and Stripe envs likewise
	// live on the backend (M1/M2).
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
		AdminToken:             getenv("ADMIN_TOKEN", "dev-only-admin-token-change-me"),
		IkaUpstreamURL:         strings.TrimRight(getenv("IKA_UPSTREAM_URL", ""), "/"),
		EncryptUpstreamURL:     strings.TrimRight(getenv("ENCRYPT_UPSTREAM_URL", ""), "/"),
		InternalAPIKey:         getenv("INTERNAL_API_KEY", ""),
		UpstreamTimeout:        time.Duration(getenvInt("UPSTREAM_TIMEOUT_SECONDS", 30)) * time.Second,
		AllowedOrigins:         splitCSV(getenv("ALLOWED_ORIGINS", "")),
		TrustedProxyCIDRs:      splitCSV(getenv("TRUSTED_PROXY_CIDRS", "")),
		DefaultRequestCost:     getenvInt("DEFAULT_REQUEST_COST", 1),
		PricingRefreshSeconds:  time.Duration(getenvInt("PRICING_REFRESH_SECONDS", 60)) * time.Second,
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
		SDKBaseURL:             strings.TrimRight(getenv("ANDROMEDA_SDK_BASE_URL", ""), "/"),
		SDKVersionTag:          getenv("ANDROMEDA_SDK_VERSION_TAG", "sdk-v0.1.0"),
		DashboardBaseURL:       strings.TrimRight(getenv("ANDROMEDA_DASHBOARD_BASE_URL", ""), "/"),
	}

	if err := cfg.validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	return cfg
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
	}
	if c.DefaultRequestCost < 1 {
		return fmt.Errorf("DEFAULT_REQUEST_COST must be >= 1")
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
		// Don't refuse to boot — we still allow env for now. But surface a
		// loud warning that operators should migrate. See docs/AUDIT_KMS.md.
		log.Printf("WARNING: ANDROMEDA_AUDIT_SIGNER=env in production. Migrate to 'vault'.")
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
