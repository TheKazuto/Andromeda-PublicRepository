package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/shinkalabs/andromeda-backend/internal/auth/oauth"
	"github.com/shinkalabs/andromeda-backend/internal/billing"
	"github.com/shinkalabs/andromeda-backend/internal/config"
	"github.com/shinkalabs/andromeda-backend/internal/notifications"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// BillingCapableStore is the union of customer auth ops, billing
// operations, customer-facing read paths (plans, balance, usage,
// gifts), and the admin console. Backend's PostgresStore satisfies all
// four; MemoryStore satisfies only the customer auth half — every other
// surface requires Postgres and fails fast with ErrNotFound when called
// against memory.
type BillingCapableStore interface {
	store.Store
	store.BillingStore
	store.CustomerStore
	store.AdminStore
	store.AdminEconomyStore
}

type Server struct {
	cfg            *config.Config
	store          BillingCapableStore
	oauthRegistry  oauth.Registry
	billing        *billing.Service
	billingWebhook *billing.WebhookHandler
	authLimiter    *authRateLimiter
	mailer         notifications.Mailer
}

// NewServer constructs the backend HTTP server.
//
// When `billingSvc` is nil or disabled, the /v1/billing/* routes are
// not mounted and the webhook returns 503. Caller passes nil in dev
// (no Stripe key) and a real *billing.Service in production.
//
// `mailer` may be nil; when nil, password-reset emails fall back to a
// log-only path so dev environments without SMTP still operate.
func NewServer(cfg *config.Config, st BillingCapableStore, billingSvc *billing.Service, billingWH *billing.WebhookHandler, mailer notifications.Mailer) *Server {
	registry := oauth.Registry{}
	if cfg.OAuth.GoogleEnabled() {
		registry["google"] = oauth.NewGoogle(
			cfg.OAuth.Google.ClientID,
			cfg.OAuth.Google.ClientSecret,
			cfg.OAuth.RedirectBase+"/v1/auth/oauth/google/callback",
		)
	}
	if cfg.OAuth.GitHubEnabled() {
		registry["github"] = oauth.NewGitHub(
			cfg.OAuth.GitHub.ClientID,
			cfg.OAuth.GitHub.ClientSecret,
			cfg.OAuth.RedirectBase+"/v1/auth/oauth/github/callback",
		)
	}
	return &Server{
		cfg:            cfg,
		store:          st,
		oauthRegistry:  registry,
		billing:        billingSvc,
		billingWebhook: billingWH,
		authLimiter:    newAuthRateLimiter(),
		mailer:         mailer,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(20 * time.Second))
	r.Use(securityHeaders(s.cfg.Env == "production"))
	r.Use(maxBodyMiddleware(defaultMaxBodyBytes))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Stripe webhook lives outside auth — Stripe-Signature is the auth
	// mechanism and the handler verifies it itself.
	if s.billing != nil && s.billing.Enabled() {
		r.Post("/v1/billing/stripe/webhook", s.handleStripeWebhook)
	}

	r.Route("/v1", func(r chi.Router) {
		// Public auth — rate-limited per IP to slow credential stuffing.
		r.Group(func(r chi.Router) {
			r.Use(s.authLimiter.middleware())
			r.Post("/auth/signup", s.handleSignup)
			r.Post("/auth/login", s.handleLogin)
			r.Get("/auth/oauth/{provider}/start", s.handleOAuthStart)
			r.Get("/auth/oauth/{provider}/callback", s.handleOAuthCallback)
			r.Post("/auth/forgot-password", s.handleForgotPassword)
			r.Post("/auth/reset-password", s.handleResetPassword)
		})
		// Refresh + logout do not enforce the auth-attempt rate limit because
		// honest clients call them on a regular cadence (every TokenTTL).
		// Refresh has its own single-use semantics + family-revocation, which
		// is the correct defense against abuse.
		r.Post("/auth/refresh", s.handleRefresh)
		r.Post("/auth/logout", s.handleLogout)
		r.Get("/auth/providers", s.handleListAuthProviders)

		// Public product surface (M3): plan catalogue + gift preview.
		r.Get("/pricing/plans", s.handlePricingPlans)
		r.Get("/gifts/preview/{token}", s.handleGiftPreview)

		// Authenticated
		r.Group(func(r chi.Router) {
			r.Use(s.RequireAuth)

			r.Get("/me", s.handleMe)
			r.Patch("/me", s.handleUpdateProfile)
			r.Delete("/me", s.handleDeleteAccount)
			r.Patch("/me/password", s.handleChangePassword)
			r.Get("/me/balance", s.handleMeBalance)
			r.Get("/me/usage", s.handleMeUsage)

			r.Get("/api-keys", s.handleListKeys)
			r.Post("/api-keys", s.handleCreateKey)
			r.Patch("/api-keys/{id}", s.handleUpdateKey)
			r.Delete("/api-keys/{id}", s.handleRevokeKey)

			// Login Social — tenant manages its OWN redirect URI allowlist
			// for the gateway OAuth broker. See oauth_redirects.go.
			r.Get("/oauth/redirects", s.handleListOAuthRedirects)
			r.Post("/oauth/redirects", s.handleAddOAuthRedirect)
			r.Delete("/oauth/redirects", s.handleDeleteOAuthRedirect)

			r.Get("/billing", s.handleBilling)

			// Gift redeem (M3) — auth required so the gift attaches
			// to the authenticated user's subscription.
			r.Post("/gifts/redeem", s.handleGiftRedeem)

			// Billing — Stripe Checkout, Portal, overage toggles.
			// Routes are only mounted when STRIPE_SECRET_KEY is set.
			if s.billing != nil && s.billing.Enabled() {
				r.Post("/billing/checkout", s.handleBillingCheckout)
				r.Post("/billing/portal", s.handleBillingPortal)
				r.Post("/billing/overage/enable", s.handleBillingOverageEnable)
				r.Post("/billing/overage/disable", s.handleBillingOverageDisable)
			}
		})
	})

	// ----- Admin auth (M4a). Login is public; everything else uses
	// requireAdminJWT so audit entries always carry an admin identity. -----
	// Login + TOTP verify are rate-limited per IP — admin TOTP brute-force
	// is the highest-impact path so the limiter sits in front of both.
	r.Route("/admin/auth", func(sub chi.Router) {
		sub.With(s.authLimiter.middleware()).Post("/login", s.handleAdminLogin)
		sub.Group(func(p chi.Router) {
			p.Use(s.requireAdminJWT)
			p.Get("/me", s.handleAdminAuthMe)
			p.Post("/totp/setup", s.handleAdminTOTPSetup)
			p.With(s.authLimiter.middleware()).Post("/totp/verify", s.handleAdminTOTPVerify)
			p.Delete("/totp", s.handleAdminTOTPDisable)
		})
	})

	// ----- Admin user management (super_admin only, JWT only) -----
	r.Route("/admin/admin-users", func(sub chi.Router) {
		sub.Use(s.requireAdminJWT)
		sub.Post("/", s.handleAdminCreateAdminUser)
		sub.Get("/", s.handleAdminListAdminUsers)
	})

	// ----- Admin audit log (read-only, JWT required) -----
	r.Route("/admin/audit", func(sub chi.Router) {
		sub.Use(s.requireAdminJWT)
		sub.Get("/", s.handleAdminAuditList)
	})

	// ----- Admin economy (M4b). Dashboard requests carry the Bearer
	// JWT; the JWT identity is attached to the request for audit. -----
	r.Route("/admin", func(adm chi.Router) {
		adm.Use(s.requireAdminJWT)

		adm.Get("/plans", s.handleAdminListPlans)
		adm.Patch("/plans/{code}", s.handleAdminUpdatePlan)

		adm.Get("/request-costs", s.handleAdminListCosts)
		adm.Patch("/request-costs/{routeKey}", s.handleAdminUpsertCost)

		adm.Post("/users", s.handleAdminCreateUser)
		adm.Post("/api-keys", s.handleAdminCreateKey)
		adm.Get("/users/{userId}/api-keys", s.handleAdminListKeys)
		adm.Patch("/users/{userId}/api-keys/{id}", s.handleAdminUpdateKey)
		adm.Delete("/users/{userId}/api-keys/{id}", s.handleAdminRevokeKey)

		adm.Post("/subscriptions", s.handleAdminAssignPlan)
		adm.Get("/users/{userId}/subscription", s.handleAdminGetSubscription)
		adm.Patch("/subscriptions/{id}/overage", s.handleAdminUpdateOverage)

		adm.Post("/credits", s.handleAdminGrantCredit)

		adm.Post("/coupons", s.handleAdminCreateCoupon)
		adm.Get("/coupons", s.handleAdminListCoupons)
		adm.Post("/coupons/{id}/refund", s.handleAdminRefundCoupon)

		adm.Post("/pricing-changes", s.handleAdminCreatePricingChange)
		adm.Get("/pricing-changes", s.handleAdminListPricingChanges)
		adm.Delete("/pricing-changes/{id}", s.handleAdminCancelPricingChange)
	})

	return r
}

// handleListAuthProviders lets the dashboard learn which OAuth providers are
// enabled at runtime, so it can hide buttons that have no backing config.
func (s *Server) handleListAuthProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"google": s.cfg.OAuth.GoogleEnabled(),
		"github": s.cfg.OAuth.GitHubEnabled(),
	})
}
