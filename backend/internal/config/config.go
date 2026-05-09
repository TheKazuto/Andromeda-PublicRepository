package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthConfig struct {
	RedirectBase string // e.g. https://api.andromeda.xyz (no trailing slash)
	DashboardURL string // e.g. https://app.andromeda.xyz (no trailing slash)
	StateSecret  string // dedicated HMAC key for the OAuth state token; falls back to JWTSecret in dev
	Google       OAuthProviderConfig
	GitHub       OAuthProviderConfig
}

func (o OAuthConfig) GoogleEnabled() bool {
	return o.Google.ClientID != "" && o.Google.ClientSecret != ""
}

func (o OAuthConfig) GitHubEnabled() bool {
	return o.GitHub.ClientID != "" && o.GitHub.ClientSecret != ""
}

type Config struct {
	Port             string
	JWTSecret        string
	AllowedOrigins   []string
	Env              string
	DatabaseURL      string
	DashboardBaseURL string
	OAuth            OAuthConfig

	// Stripe billing — empty disables /v1/billing/*. Production requires
	// the full set; the gateway README has the Stripe Dashboard setup
	// instructions (products, prices, meter, webhook endpoint).
	StripeSecretKey     string
	StripeWebhookSecret string
	StripePriceIDsJSON  string
	CheckoutSuccessURL  string
	CheckoutCancelURL   string

	// SMTP — when SMTPHost is empty, notification workers log instead
	// of sending. Gift purchase emails, quota threshold alerts and
	// pricing-change announcements all go through this single mailer.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	// Admin console (M4). Empty AdminJWTSecret disables JWT-based admin
	// auth — the dashboard /admin/* surface won't work, but the legacy
	// X-Admin-Token shared secret still gates the operator paths used
	// by CLI scripts.
	AdminJWTSecret         string
	AdminToken             string
	AdminBootstrapEmail    string
	AdminBootstrapPassword string
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		Port:             getenv("PORT", "8080"),
		JWTSecret:        getenv("JWT_SECRET", "dev-only-secret-change-me"),
		AllowedOrigins:   splitCSV(getenv("ALLOWED_ORIGINS", "http://localhost:3000")),
		Env:              getenv("ENV", "development"),
		DatabaseURL:      getenv("DATABASE_URL", ""),
		DashboardBaseURL: strings.TrimRight(getenv("ANDROMEDA_DASHBOARD_BASE_URL", ""), "/"),
		StripeSecretKey:     getenv("STRIPE_SECRET_KEY", ""),
		StripeWebhookSecret: getenv("STRIPE_WEBHOOK_SECRET", ""),
		StripePriceIDsJSON:  getenv("STRIPE_PRICES_JSON", ""),
		CheckoutSuccessURL:  strings.TrimRight(getenv("STRIPE_CHECKOUT_SUCCESS_URL", ""), "/"),
		CheckoutCancelURL:   strings.TrimRight(getenv("STRIPE_CHECKOUT_CANCEL_URL", ""), "/"),
		SMTPHost:     strings.TrimSpace(getenv("SMTP_HOST", "")),
		SMTPPort:     getenvInt("SMTP_PORT", 587),
		SMTPUsername: getenv("SMTP_USERNAME", ""),
		SMTPPassword: getenv("SMTP_PASSWORD", ""),
		SMTPFrom:     getenv("SMTP_FROM", ""),

		AdminJWTSecret:         getenv("ADMIN_JWT_SECRET", ""),
		AdminToken:             getenv("ADMIN_TOKEN", ""),
		AdminBootstrapEmail:    strings.ToLower(strings.TrimSpace(getenv("ANDROMEDA_BOOTSTRAP_ADMIN_EMAIL", ""))),
		AdminBootstrapPassword: getenv("ANDROMEDA_BOOTSTRAP_ADMIN_PASSWORD", ""),
		OAuth: OAuthConfig{
			RedirectBase: strings.TrimRight(getenv("OAUTH_REDIRECT_BASE", ""), "/"),
			DashboardURL: strings.TrimRight(getenv("DASHBOARD_URL", "http://localhost:3000"), "/"),
			StateSecret:  getenv("OAUTH_STATE_SECRET", ""),
			Google: OAuthProviderConfig{
				ClientID:     getenv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getenv("GOOGLE_CLIENT_SECRET", ""),
			},
			GitHub: OAuthProviderConfig{
				ClientID:     getenv("GITHUB_CLIENT_ID", ""),
				ClientSecret: getenv("GITHUB_CLIENT_SECRET", ""),
			},
		},
	}

	// Compromise of JWT_SECRET should not also forge OAuth state tokens —
	// require a dedicated secret in production. In development we fall back
	// to JWT_SECRET so /v1/auth/oauth/* keeps working without extra setup.
	if cfg.OAuth.StateSecret == "" {
		if cfg.Env == "production" && (cfg.OAuth.GoogleEnabled() || cfg.OAuth.GitHubEnabled()) {
			log.Fatal("OAUTH_STATE_SECRET must be set in production when any OAuth provider is configured")
		}
		cfg.OAuth.StateSecret = cfg.JWTSecret
	} else if len(cfg.OAuth.StateSecret) < 32 {
		log.Fatal("OAUTH_STATE_SECRET must be at least 32 bytes")
	}

	if cfg.Env == "production" && cfg.JWTSecret == "dev-only-secret-change-me" {
		log.Fatal("JWT_SECRET must be set in production")
	}

	if cfg.Env == "production" && cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL must be set in production")
	}

	if (cfg.OAuth.GoogleEnabled() || cfg.OAuth.GitHubEnabled()) && cfg.OAuth.RedirectBase == "" {
		log.Fatal("OAUTH_REDIRECT_BASE must be set when any OAuth provider is configured")
	}

	if cfg.AdminJWTSecret != "" && len(cfg.AdminJWTSecret) < 32 {
		log.Fatal("ADMIN_JWT_SECRET must be at least 32 bytes")
	}
	if (cfg.AdminBootstrapEmail == "") != (cfg.AdminBootstrapPassword == "") {
		log.Fatal("ANDROMEDA_BOOTSTRAP_ADMIN_EMAIL and ANDROMEDA_BOOTSTRAP_ADMIN_PASSWORD must be set together (or both empty)")
	}
	if cfg.Env == "production" && cfg.AdminToken != "" && len(cfg.AdminToken) < 32 {
		log.Fatal("ADMIN_TOKEN must be at least 32 bytes in production (or unset to disable)")
	}

	return cfg
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

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
