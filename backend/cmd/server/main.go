package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shinkalabs/andromeda-backend/internal/api"
	backendauth "github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/billing"
	"github.com/shinkalabs/andromeda-backend/internal/config"
	"github.com/shinkalabs/andromeda-backend/internal/notifications"
	"github.com/shinkalabs/andromeda-backend/internal/pricing"
	"github.com/shinkalabs/andromeda-backend/internal/store"
	"github.com/shinkalabs/andromeda-backend/internal/webhooks"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, pgStore, err := buildStore(cfg)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	defer func() { _ = st.Close() }()

	// --- Mailer (SMTP, opt-in) ---
	// One mailer drives every email side effect: gift purchase receipts,
	// quota threshold alerts, pricing-change announcements. When the
	// SMTP envs are empty, the mailer is a noop logger.
	mailer := notifications.NewSMTPMailer(notifications.SMTPConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	}, logger)

	// --- Billing (Stripe) ---
	// Backend owns the billing pipeline now (M1 of the architecture
	// split). Required Postgres because BillingStore queries the
	// gateway-owned tables — pgStore is nil under the in-memory dev
	// store, in which case billing stays disabled.
	var (
		billingSvc *billing.Service
		billingWH  *billing.WebhookHandler
	)
	if pgStore != nil {
		var err error
		billingSvc, err = billing.New(billing.Options{
			APIKey:        cfg.StripeSecretKey,
			WebhookSecret: cfg.StripeWebhookSecret,
			PriceIDsJSON:  cfg.StripePriceIDsJSON,
			SuccessURL:    cfg.CheckoutSuccessURL,
			CancelURL:     cfg.CheckoutCancelURL,
			Logger:        logger,
		})
		if err != nil {
			log.Fatalf("billing init: %v", err)
		}
		if billingSvc.Enabled() {
			billingWH = billing.NewWebhookHandler(billingSvc, pgStore, logger).
				WithGiftObserver(notifications.NewGiftObserver(
					mailer, cfg.DashboardBaseURL, cfg.SMTPFrom, logger,
				))
			logger.Info("billing service ready", "webhook", cfg.StripeWebhookSecret != "")

			// Overage reporting worker — sends meter events to Stripe
			// every 5 min for subscriptions with active overage.
			ow := notifications.NewOverageWorker(notifications.OverageWorkerOptions{
				Store:   pgStore,
				Billing: billingSvc,
				Logger:  logger,
			})
			go ow.Start(rootCtx)
		} else {
			logger.Info("billing service disabled — STRIPE_SECRET_KEY not configured")
		}
	} else {
		logger.Info("billing service disabled — running on in-memory store")
	}

	// --- Notification + applier workers (require Postgres) ---
	if pgStore != nil {
		whPub := webhooks.NewPublisher(pgStore.Pool())

		quotaWorker := notifications.NewQuotaWorker(notifications.QuotaWorkerOptions{
			Store:        pgStore,
			Mailer:       mailer,
			Publisher:    whPub,
			DashboardURL: cfg.DashboardBaseURL,
			FromAddr:     cfg.SMTPFrom,
			Logger:       logger,
		})
		go quotaWorker.Start(rootCtx)

		pricingNotifWorker := notifications.NewPricingWorker(notifications.PricingWorkerOptions{
			Store:        pgStore,
			Mailer:       mailer,
			Publisher:    whPub,
			DashboardURL: cfg.DashboardBaseURL,
			FromAddr:     cfg.SMTPFrom,
			Logger:       logger,
		})
		go pricingNotifWorker.Start(rootCtx)

		// Pricing applier — copies due pricing_history rows into the
		// live tables (request_costs / plans). The gateway picks up
		// changes on its own pricer cache refresh (60s).
		applierWorker := pricing.NewApplier(pgStore, logger)
		go applierWorker.Start(rootCtx)

		logger.Info("notification + applier workers started",
			"smtp_configured", cfg.SMTPHost != "")
	}

	// The backend's Server expects a billingCapableStore. Memory store
	// doesn't satisfy it; in dev we still pass the *store.Store via
	// adapter that returns 503 from billing methods. Production always
	// uses *PostgresStore which satisfies both.
	var capable api.BillingCapableStore = pgStore
	if capable == nil {
		capable = unsupportedBillingStore{Store: st}
	}

	// Bootstrap the first super_admin from envs when admin_users is empty.
	// Skipped silently when Postgres isn't wired or the bootstrap envs
	// aren't set. Errors are logged but never fatal — the operator can
	// always create an admin via SQL or fix envs and restart.
	if pgStore != nil && cfg.AdminBootstrapEmail != "" {
		bctx, bcancel := context.WithTimeout(rootCtx, 10*time.Second)
		if err := bootstrapAdmin(bctx, pgStore, cfg.AdminBootstrapEmail, cfg.AdminBootstrapPassword); err != nil {
			logger.Warn("admin bootstrap failed", "err", err)
		}
		bcancel()
	}

	srv := api.NewServer(cfg, capable, billingSvc, billingWH, mailer)

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("andromeda-backend listening on :%s (env=%s)", cfg.Port, cfg.Env)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	_ = httpServer.Shutdown(ctx)
	cancel()
}

// buildStore returns the customer-facing Store (auth, api keys) and,
// when running on Postgres, the same *PostgresStore typed as the
// billing-capable concrete type so main.go can hand it to billing.
func buildStore(cfg *config.Config) (store.Store, *store.PostgresStore, error) {
	if cfg.DatabaseURL == "" {
		log.Println("warning: DATABASE_URL not set — using in-memory store (data will be lost on restart)")
		return store.NewMemory(), nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return nil, nil, err
	}
	pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return pg, pg, nil
}

// bootstrapAdmin creates the first super_admin row from env-supplied
// credentials when admin_users is empty. Idempotent — once the table
// has any row, the function is a no-op.
func bootstrapAdmin(ctx context.Context, st *store.PostgresStore, email, password string) error {
	n, err := st.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("count admin users: %w", err)
	}
	if n > 0 {
		return nil
	}
	hashed, err := backendauth.HashAdminPassword(password)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}
	if _, err := st.CreateAdminUser(ctx, store.AdminUserCreate{
		Email:          email,
		HashedPassword: hashed,
		Role:           "super_admin",
		MFARequired:    false,
	}); err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}
	log.Printf("bootstrap admin created (role=super_admin, mfa_required=false — set up TOTP after first login)")
	return nil
}

// unsupportedBillingStore wraps the in-memory Store and returns
// ErrNotFound for every BillingStore method. Lets the backend keep
// running in dev without Postgres while keeping the Server type
// strict — billing handlers are not mounted in this case, so these
// methods are never actually called.
type unsupportedBillingStore struct {
	store.Store
}

func (unsupportedBillingStore) SetUserStripeCustomerID(context.Context, string, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) RotateRefreshToken(context.Context, string, store.RefreshTokenIssue) (string, error) {
	return "", store.ErrNotFound
}
func (unsupportedBillingStore) GetUserByStripeCustomerID(context.Context, string) (*store.User, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) AssignPlan(context.Context, string, string) (*store.Subscription, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetActiveSubscription(context.Context, string) (*store.Subscription, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetSubscriptionByStripeID(context.Context, string) (*store.Subscription, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) SetSubscriptionStripeIDs(context.Context, string, string, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) SetSubscriptionStatus(context.Context, string, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) UpdateSubscription(context.Context, string, store.SubscriptionMutation) (*store.Subscription, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) SetSubscriptionOverageItem(context.Context, string, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) AdvanceOverageReported(context.Context, string, int64) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) ListSubscriptionsForOverageReport(context.Context) ([]store.OverageReportTarget, error) {
	return nil, nil
}
func (unsupportedBillingStore) CreateGiftCard(context.Context, store.GiftCardCreate) (*store.GiftCard, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) MarkStripeEventProcessed(context.Context, string, string, string) (bool, error) {
	return false, store.ErrNotFound
}
func (unsupportedBillingStore) UnmarkStripeEventProcessed(context.Context, string) error {
	return store.ErrNotFound
}

// CustomerStore stubs — only callable when running on Postgres in
// production. Memory dev mode never serves /v1/pricing/plans, /v1/me/*
// or /v1/gifts/* against real data.
func (unsupportedBillingStore) ListPlans(context.Context) ([]store.Plan, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetPlanByCode(context.Context, string) (*store.Plan, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ComputeBalance(context.Context, string) (*store.Balance, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) SumActiveCredits(context.Context, string) (int64, error) {
	return 0, store.ErrNotFound
}
func (unsupportedBillingStore) GetUsageReport(context.Context, string, time.Time, time.Time, int) (*store.UsageReport, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetGiftCardByToken(context.Context, string) (*store.GiftCard, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ApplyGiftCard(context.Context, string, string) (*store.GiftCardRedemption, error) {
	return nil, store.ErrNotFound
}

// AdminStore stubs — same posture as the rest of unsupportedBillingStore.
// Memory dev mode never serves /admin/*, so these methods are unreachable
// in practice; they exist only to satisfy the BillingCapableStore union.
func (unsupportedBillingStore) CreateAdminUser(context.Context, store.AdminUserCreate) (*store.AdminUser, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetAdminUserByEmail(context.Context, string) (*store.AdminUser, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GetAdminUserByID(context.Context, string) (*store.AdminUser, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ListAdminUsers(context.Context) ([]store.AdminUser, error) {
	return nil, nil
}
func (unsupportedBillingStore) TouchAdminLogin(context.Context, string, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) SetAdminMFASecret(context.Context, string, string, bool) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) DeactivateAdminUser(context.Context, string) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) CountAdminUsers(context.Context) (int, error) {
	return 0, nil
}
func (unsupportedBillingStore) AppendAdminAudit(context.Context, store.AdminAuditAppend) error {
	return nil
}
func (unsupportedBillingStore) ListAdminAudit(context.Context, int) ([]store.AdminAuditEntry, error) {
	return nil, nil
}
func (unsupportedBillingStore) IncrementAdminFailedLogin(context.Context, string, int, time.Duration) error {
	return nil
}
func (unsupportedBillingStore) ResetAdminFailedLogin(context.Context, string) error {
	return nil
}
func (unsupportedBillingStore) IsAdminLocked(context.Context, string) (bool, *time.Time, error) {
	return false, nil, nil
}

// AdminEconomyStore stubs (M4b). Same posture: unreachable in dev.
func (unsupportedBillingStore) UpdatePlan(context.Context, string, store.PlanMutation) (*store.Plan, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ListRequestCosts(context.Context) ([]store.RequestCost, error) {
	return nil, nil
}
func (unsupportedBillingStore) UpsertRequestCost(context.Context, store.RequestCost) error {
	return store.ErrNotFound
}
func (unsupportedBillingStore) UpdateAPIKey(context.Context, string, string, store.APIKeyMutation) (*store.APIKey, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) GrantCredit(context.Context, store.CreditGrant) (*store.Credit, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) RefundGiftCard(context.Context, string) (*store.GiftCard, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ListGiftCardsForAdmin(context.Context, string, string) ([]store.GiftCard, error) {
	return nil, nil
}
func (unsupportedBillingStore) CreatePricingChange(context.Context, store.PricingChangeCreate) (*store.PricingChange, error) {
	return nil, store.ErrNotFound
}
func (unsupportedBillingStore) ListPendingPricingChanges(context.Context) ([]store.PricingChange, error) {
	return nil, nil
}
func (unsupportedBillingStore) ListPricingChangesByTarget(context.Context, string, string) ([]store.PricingChange, error) {
	return nil, nil
}
func (unsupportedBillingStore) CancelPricingChange(context.Context, int64) error {
	return store.ErrNotFound
}
