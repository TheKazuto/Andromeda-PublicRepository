package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/shinkalabs/andromeda-gateway/internal/api"
	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/futuresign"
	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
	gwmetrics "github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
	"github.com/shinkalabs/andromeda-gateway/internal/observability"
	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/pricing"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/redisclient"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
	"github.com/shinkalabs/andromeda-gateway/internal/usage"
	"github.com/shinkalabs/andromeda-gateway/internal/webhooks"
)

func main() {
	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))

	// Flush non-fatal config advisories now that the logger exists.
	for _, w := range cfg.Warnings {
		logger.Warn("config advisory", "detail", w)
	}

	// SSRF guard for tenant-supplied callback URLs (webhook deliveries,
	// future-sign external watchers). Production refuses anything but https
	// to a public IP; development additionally allows http://localhost so
	// the loopback dev stack works.
	urlGuardMode := netsafety.ModeProduction
	if !cfg.IsProduction() {
		urlGuardMode = netsafety.ModeDevelopment
	}
	urlGuard := netsafety.New(urlGuardMode)

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- OpenTelemetry tracing (opt-in via OTEL_EXPORTER_OTLP_ENDPOINT) ---
	// Returns a no-op shutdown when env is unset; otelhttp Transport /
	// Handler wrapping in upstream + server is then a free pass-through.
	otelShutdown, err := observability.Init(rootCtx, "0.1.0", logger)
	if err != nil {
		logger.Warn("otel init failed — continuing without tracing", "err", err)
	}
	defer func() {
		shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if err := otelShutdown(shutCtx); err != nil {
			logger.Warn("otel shutdown error", "err", err)
		}
	}()

	// workersWG tracks every long-running background goroutine so the
	// graceful-shutdown path can wait for them to drain before the
	// process exits. Each `spawn` call adds one to the group.
	var workersWG sync.WaitGroup
	spawn := func(name string, fn func(context.Context)) {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			fn(rootCtx)
			logger.Debug("worker exited", "name", name)
		}()
	}

	// --- Postgres ---
	bootCtx, bootCancel := context.WithTimeout(rootCtx, 30*time.Second)
	defer bootCancel()
	db, err := store.NewPostgres(bootCtx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database initialisation failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database ready")

	// --- Redis (shared between rate limit and idempotency) ---
	rdb, err := redisclient.New(cfg.RedisURL, logger)
	if err != nil {
		logger.Error("redis client init failed", "err", err)
		os.Exit(1)
	}
	if rdb != nil {
		defer func() { _ = rdb.Close() }()
	}

	// --- Rate limit (Redis) ---
	limiter, err := ratelimit.New(cfg.RedisURL, cfg.RateLimitFailOpen, logger)
	if err != nil {
		logger.Error("rate limiter init failed", "err", err)
		os.Exit(1)
	}

	// --- Pricing cache ---
	pricer := pricing.New(db, cfg.DefaultRequestCost, cfg.PricingRefreshSeconds, logger)
	spawn("pricer", pricer.Start)

	// Pricing-history applier moved to backend (M2 of architecture
	// split). Backend applies due rows; gateway picks up changes on
	// the next pricer cache refresh (60s).

	// Admin bootstrap moved to the backend service in M4.

	// --- Usage recorder ---
	recorder := usage.NewRecorder(db, logger)
	recorder.Start(rootCtx)

	// --- Metrics (Prometheus) ---
	metrics, metricsHandler := gwmetrics.New()
	logger.Info("metrics registry ready")

	// --- Upstreams (with circuit-breaker trip observer feeding metrics) ---
	tripObserver := func(name string) {
		metrics.CircuitBreakerTripsTotal.WithLabelValues(name).Inc()
		logger.Warn("upstream circuit breaker tripped open", "upstream", name)
	}
	ups, err := upstream.NewRegistryWithObserver(cfg, tripObserver)
	if err != nil {
		logger.Error("upstream registry init failed", "err", err)
		os.Exit(1)
	}

	// --- Audit log signer ---
	auditRec, err := buildAuditRecorder(cfg, db, logger)
	if err != nil {
		logger.Error("audit recorder init failed", "err", err)
		os.Exit(1)
	}
	logger.Info("audit recorder ready",
		"signer", cfg.AuditSignerKind,
		"audit_pubkey_b64", auditRec.PublicKeyBase64())

	// --- Webhook system ---
	whStore := webhooks.NewStore(db.Pool())
	whDispatcher := webhooks.NewDispatcher(whStore, logger).
		WithURLGuard(urlGuard).
		WithMetrics(metrics)
	spawn("webhook-dispatcher", whDispatcher.Run)
	whPublisher := webhooks.NewPublisher(whStore).WithMetrics(metrics)

	// Notification workers (mailer, quota, pricing) and the gift
	// purchase observer moved to backend (M2 of architecture split).
	// Backend reads/writes the same Postgres tables; the webhook
	// dispatcher below still claims and POSTs deliveries.

	// --- Policy subscriptions (policy PDA → api_key mapping) ---
	policySubsStore := policy.NewSubscriptionsStore(db.Pool())

	// --- Solana log listener (Phase 2 — IDL-aware parser) ---
	// Tenant resolver = policy_subscriptions lookup. Each on-chain event the
	// listener decodes is now routed to the api_key that owns the policy PDA.
	listenerProgramIDs := collectListenerProgramIDs(cfg)
	if cfg.SolanaRPCURL != "" && len(listenerProgramIDs) > 0 {
		resolver := webhooks.PolicyTenantResolver(func(ctx context.Context, addr string) (uuid.UUID, bool) {
			// ResolveAny handles both Andromeda policy events (Policy →
			// policy_address) and Ika dWallet events (Dwallet → dwallet_address).
			return policySubsStore.ResolveAny(ctx, addr)
		})
		listener := webhooks.NewListener(cfg.SolanaRPCURL, listenerProgramIDs, whPublisher, resolver, logger).
			WithDropObserver(func(reason string) {
				metrics.ListenerEventsDropped.WithLabelValues(reason).Inc()
			})
		spawn("solana-listener", listener.Start)
	} else {
		logger.Info("solana listener disabled — set SOLANA_RPC_URL and at least one program ID")
	}

	// --- Future-Sign trigger watcher (Sprint 4 — off-chain) ---
	fsStore := futuresign.NewStore(db.Pool())
	fsWatcherRunning := false
	if cfg.IkaUpstreamURL != "" && cfg.InternalAPIKey != "" {
		fsWatcher := futuresign.NewWatcher(futuresign.WatcherOptions{
			Store:     fsStore,
			Ika:       futuresign.NewHTTPCompleter(cfg.IkaUpstreamURL, cfg.InternalAPIKey),
			Publisher: whPublisher,
			Logger:    logger,
			URLGuard:  urlGuard,
		})
		fsWatcher.Start(rootCtx)
		fsWatcherRunning = true
		logger.Info("future-sign watcher running",
			"slot_time_tick", "5s", "external_webhook_tick", "30s")
	} else {
		logger.Info("future-sign watcher disabled — IKA_UPSTREAM_URL and INTERNAL_API_KEY not set")
	}

	// --- PolicyEngine v3 service (optional — needs ANDROMEDA_POLICY_ENGINE_PROGRAM_ID).
	// Owns its own Solana RPC client + gas sponsor — the legacy `policies`
	// package (8 mutually-exclusive templates) was retired on 2026-05-16 as
	// part of F-CLEANUP-LEGACY-TOTAL. The program is deployed in devnet at
	// ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL (F14, 2026-05-15).
	var policyV3Svc *policy.Service
	if cfg.PolicyEngineProgramID != "" {
		pid, err := solana.PublicKeyFromBase58(cfg.PolicyEngineProgramID)
		if err != nil {
			logger.Error("policy-engine v3: invalid ANDROMEDA_POLICY_ENGINE_PROGRAM_ID", "err", err)
			os.Exit(1)
		}
		policyV3Svc = policy.NewService(pid)
		if cfg.SolanaRPCURL != "" {
			rpcClient := rpc.New(cfg.SolanaRPCURL)
			policyV3Svc.WithRPC(rpcClient)
			if cfg.GasSponsorKeypairJSON != "" {
				sponsor, err := gasponsor.New(cfg.GasSponsorKeypairJSON, rpcClient)
				if err != nil {
					logger.Error("gas sponsor init failed", "err", err)
					os.Exit(1)
				}
				policyV3Svc.WithGasSponsor(sponsor)
				logger.Info("gas sponsor ready", "public_key", sponsor.PublicKey().String())
			} else {
				logger.Warn("gas sponsor disabled - set ANDROMEDA_GAS_SPONSOR_KEYPAIR to enable policy submit endpoints")
			}
		} else {
			logger.Warn("policy-engine v3: SOLANA_RPC_URL empty — /submit endpoints will return 503")
		}
		logger.Info("policy-engine v3 service ready", "program_id", pid.String())
	} else {
		logger.Info("policy-engine v3 disabled — set ANDROMEDA_POLICY_ENGINE_PROGRAM_ID to enable")
	}

	// Billing migrated to backend (M1 of architecture split). Gateway
	// no longer boots a Stripe service or overage worker — those live
	// in `backend/cmd/server`.

	// --- HTTP server ---
	srv := api.NewServer(api.Deps{
		Config:              cfg,
		Store:               db,
		Limiter:             limiter,
		Pricer:              pricer,
		Usage:               recorder,
		Upstreams:           ups,
		Redis:               rdb,
		Audit:               auditRec,
		WebhookStore:        whStore,
		PolicyV3Service:     policyV3Svc,
		PolicySubscriptions: policySubsStore,
		FutureSignStore:          fsStore,
		FutureSignWatcherRunning: fsWatcherRunning,
		Metrics:                  metrics,
		MetricsHandler:      metricsHandler,
		URLGuard:            urlGuard,
		Logger:              logger,
	})

	// Background scraper that pushes runtime gauges (usage buffer +
	// breaker state + webhook DLQ depth) into Prometheus collectors
	// every 15s. Counters update inline from request handlers; gauges
	// only need a periodic refresh.
	spawn("metrics-scraper", func(ctx context.Context) {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		updateGauges(ctx, metrics, recorder, ups, whStore)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				updateGauges(ctx, metrics, recorder, ups, whStore)
			}
		}
	})
	// Wrap the router with otelhttp.NewHandler so every incoming request
	// gets a server span. The chi route pattern is propagated via the
	// metrics middleware; combined with otelhttp this gives clean span
	// names like "GET /v1/dwallet/{id}".
	rootHandler := otelhttp.NewHandler(srv.Router(), "gateway",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           rootHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("gateway listening", "port", cfg.Port, "env", cfg.Env)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server error", "err", err)
			cancel()
		}
	}()

	// --- Graceful shutdown ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
		logger.Info("shutdown signal received")
	case <-rootCtx.Done():
	}

	// Two-phase shutdown:
	//   1. Stop accepting new HTTP connections (Shutdown), giving in-flight
	//      requests up to 15s to finish.
	//   2. Cancel rootCtx so every background worker (pricer, applier,
	//      quota/pricing/overage notifications, webhook dispatcher,
	//      listener, recorder) exits its loop. Wait on the WaitGroup for
	//      them to drain — bounded by a hard 20s deadline so a stuck
	//      worker can't keep the process around forever.
	httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer httpShutdownCancel()
	if err := httpSrv.Shutdown(httpShutdownCtx); err != nil {
		logger.Error("http shutdown error", "err", err)
	}

	cancel()

	workersCtx, workersCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer workersCancel()
	workersDone := make(chan struct{})
	go func() {
		workersWG.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
		logger.Info("all background workers drained")
	case <-workersCtx.Done():
		logger.Warn("worker shutdown timeout — exiting with stragglers")
	}
	<-recorder.Done()

	if drops := recorder.Drops(); drops > 0 {
		logger.Warn("usage events dropped during this run", "total_drops", drops)
	}
	logger.Info("gateway stopped")
}

// buildAuditRecorder selects the signer backend based on cfg.AuditSignerKind:
//   - "env"   keeps the ed25519 key in process memory (DEV only).
//   - "vault" calls HashiCorp Vault Transit Engine for every signature.
//
// Both paths share the same Recorder — only Signer differs.
func buildAuditRecorder(cfg *config.Config, db store.Store, logger *slog.Logger) (*audit.Recorder, error) {
	switch cfg.AuditSignerKind {
	case "vault":
		signer, err := audit.NewVaultTransitSigner(audit.VaultConfig{
			Addr:      cfg.AuditVaultAddr,
			Token:     cfg.AuditVaultToken,
			KeyName:   cfg.AuditVaultKeyName,
			PubKeyB64: cfg.AuditVaultPubKeyB64,
		})
		if err != nil {
			return nil, err
		}
		return audit.NewRecorderWithSigner(db.Pool(), signer, logger), nil
	default:
		return audit.NewRecorder(db.Pool(), cfg.AuditPrivateKeyB64, logger)
	}
}

// collectListenerProgramIDs gathers every Quasar program ID we want the Solana
// listener to observe: the Ika main program plus every template ID configured
// via ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON. Duplicates and empty values are
// stripped.
func collectListenerProgramIDs(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(cfg.IkaProgramID)
	if cfg.TemplateProgramIDsJSON != "" {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(cfg.TemplateProgramIDsJSON), &parsed); err == nil {
			for _, v := range parsed {
				add(v)
			}
		}
	}
	return out
}

// updateGauges refreshes Prometheus gauges that need periodic sampling.
// Inline counters (HTTP, quota, rate-limit) tick on every request, but
// gauges (buffer depth, breaker state, DLQ depth) need a polling source.
func updateGauges(ctx context.Context, m *gwmetrics.Metrics, recorder *usage.Recorder, ups *upstream.Registry, whStore *webhooks.Store) {
	if recorder != nil {
		m.UsageBufferDepth.Set(float64(recorder.BufferDepth()))
	}
	for _, name := range []string{"ika", "encrypt"} {
		t := ups.Get(name)
		state := stateToFloat(t.State())
		m.CircuitBreakerState.WithLabelValues(name).Set(state)
	}
	if whStore != nil {
		dlqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if depth, err := whStore.CountDLQ(dlqCtx); err == nil {
			m.WebhookDLQDepth.Set(float64(depth))
		}
	}
}

// stateToFloat encodes the breaker state as a Prometheus-friendly number.
func stateToFloat(state string) float64 {
	switch state {
	case "open":
		return 1
	case "half-open":
		return 2
	default:
		return 0
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
