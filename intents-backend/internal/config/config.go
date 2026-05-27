// Package config loads and validates the intents-backend environment.
//
// The service is a stateless private engine: the gateway is its only caller
// (X-Internal-Key) and owns all multi-tenant auth, rate-limit, quota and
// billing. This config therefore only covers the LI.FI aggregator, the
// optional RPC overrides, and the integrator-fee guardrails.
package config

import (
	"encoding/json"
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

	// InternalAPIKey is the shared secret the gateway sends as X-Internal-Key.
	// Required in production; the auth middleware rejects every request when set.
	InternalAPIKey string

	// LI.FI aggregator.
	LifiBaseURL         string
	LifiAPIKey          string
	LifiIntegrator      string
	LifiFeeBps          int
	LifiFeeMaxBps       int
	LifiFeeWalletSolana string
	LifiFeeWalletEVM    string
	LifiTimeout         time.Duration

	// RPC overrides (optional). Empty = broadcast/simulate use the public RPCs
	// the LI.FI /chains endpoint publishes. Setting these points the operator at
	// a dedicated provider (Helius/Alchemy) without a code change.
	SolanaRPCURL   string
	EVMRPCURLsJSON string
	SuiRPCURL      string

	// QuoteCacheTTL is the lifetime of a cached quote PREVIEW (display-only;
	// the transactionRequest is never cached). Short by design so prices stay
	// fresh while repeated identical quotes are absorbed. 0 disables the cache.
	QuoteCacheTTL time.Duration

	// Warnings collects non-fatal advisories surfaced by validate(); main()
	// flushes them through slog once the logger exists.
	Warnings []string
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		Port:                getenv("PORT", "8082"),
		Env:                 getenv("ENV", "development"),
		LogLevel:            getenv("LOG_LEVEL", "info"),
		InternalAPIKey:      getenv("INTERNAL_API_KEY", ""),
		LifiBaseURL:         strings.TrimRight(getenv("LIFI_API_BASE_URL", "https://li.quest/v1"), "/"),
		LifiAPIKey:          getenv("LIFI_API_KEY", ""),
		LifiIntegrator:      getenv("LIFI_INTEGRATOR", "andromeda"),
		LifiFeeBps:          getenvInt("LIFI_FEE_BPS", 0),
		LifiFeeMaxBps:       getenvInt("LIFI_FEE_MAX_BPS", 200),
		LifiFeeWalletSolana: getenv("LIFI_FEE_WALLET_SOLANA", ""),
		LifiFeeWalletEVM:    getenv("LIFI_FEE_WALLET_EVM", ""),
		LifiTimeout:         time.Duration(getenvInt("LIFI_TIMEOUT_SECONDS", 20)) * time.Second,
		SolanaRPCURL:        strings.TrimRight(getenv("SOLANA_RPC_URL", ""), "/"),
		EVMRPCURLsJSON:      getenv("EVM_RPC_URLS_JSON", "{}"),
		SuiRPCURL:           strings.TrimRight(getenv("SUI_RPC_URL", ""), "/"),
		QuoteCacheTTL:       time.Duration(getenvInt("QUOTE_CACHE_TTL_SECONDS", 5)) * time.Second,
	}

	if err := cfg.validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	return cfg
}

func (c *Config) validate() error {
	// Fee guardrail (financial safety before revenue): refuse to boot if the
	// configured integrator fee exceeds the safety ceiling. A typo here would
	// silently overcharge every swap.
	if c.LifiFeeMaxBps < 0 || c.LifiFeeMaxBps > 10000 {
		return fmt.Errorf("LIFI_FEE_MAX_BPS must be in [0, 10000] (got %d)", c.LifiFeeMaxBps)
	}
	if c.LifiFeeBps < 0 {
		return fmt.Errorf("LIFI_FEE_BPS must be >= 0 (got %d)", c.LifiFeeBps)
	}
	if c.LifiFeeBps > c.LifiFeeMaxBps {
		return fmt.Errorf("LIFI_FEE_BPS (%d) exceeds LIFI_FEE_MAX_BPS (%d)", c.LifiFeeBps, c.LifiFeeMaxBps)
	}
	if c.LifiTimeout <= 0 {
		return fmt.Errorf("LIFI_TIMEOUT_SECONDS must be positive")
	}

	if c.Env == "production" {
		if c.InternalAPIKey == "" {
			return fmt.Errorf("INTERNAL_API_KEY is required in production (shared with the gateway)")
		}
		if c.LifiAPIKey == "" {
			c.Warnings = append(c.Warnings,
				"LIFI_API_KEY is empty in production — LI.FI rate limits will be tighter without a key")
		}
		if c.LifiFeeBps > 0 && c.LifiFeeWalletSolana == "" {
			c.Warnings = append(c.Warnings,
				"LIFI_FEE_BPS > 0 but LIFI_FEE_WALLET_SOLANA is empty — confirm fee collection mechanics in the LI.FI portal")
		}
	}
	return nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// EVMRPCOverrides parses EVM_RPC_URLS_JSON ({"<chainId>":"<url>"}) into a
// chainId→URL map. Invalid JSON or non-numeric keys yield an empty map (the
// broadcast then falls back to the public RPCs from LI.FI /chains).
func (c *Config) EVMRPCOverrides() map[int]string {
	out := map[int]string{}
	raw := strings.TrimSpace(c.EVMRPCURLsJSON)
	if raw == "" || raw == "{}" {
		return out
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		c.Warnings = append(c.Warnings, "EVM_RPC_URLS_JSON is not valid JSON — ignored")
		return out
	}
	for k, v := range m {
		id, err := strconv.Atoi(strings.TrimSpace(k))
		if err != nil || strings.TrimSpace(v) == "" {
			continue
		}
		out[id] = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	return out
}

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
