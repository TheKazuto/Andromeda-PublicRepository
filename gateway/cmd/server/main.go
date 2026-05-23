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
	"github.com/sony/gobreaker/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/shinkalabs/andromeda-gateway/internal/api"
	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/futuresign"
	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
	"github.com/shinkalabs/andromeda-gateway/internal/leader"
	gwmetrics "github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
	"github.com/shinkalabs/andromeda-gateway/internal/observability"
	"github.com/shinkalabs/andromeda-gateway/internal/oraclemonitor"
	"github.com/shinkalabs/andromeda-gateway/internal/oraclerelay"
	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/pricing"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/redisclient"
	"github.com/shinkalabs/andromeda-gateway/internal/risk"
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
	// Observer is attached after metrics are constructed below — see the
	// `limiter.WithObserver(metrics)` call after `gwmetrics.New()`.

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

	// Attach observers now that metrics exist — the rate limiter exports
	// Redis eval latency + error/fail-open counters via this hook.
	limiter = limiter.WithObserver(metrics)

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
	auditRec.WithObserver(metrics)
	logger.Info("audit recorder ready",
		"signer", cfg.AuditSignerKind,
		"audit_pubkey_b64", auditRec.PublicKeyBase64())

	// P1.4: signer outbox worker. Append() no longer signs inline —
	// rows land with signature NULL and the worker below drains the
	// queue. Runs on every replica because FOR UPDATE SKIP LOCKED
	// partitions safely; chain integrity is preserved by entry_hash.
	auditSigner := auditRec.SignerForWorker()
	auditWorker := audit.NewSignerWorker(db.Pool(), auditSigner, logger, audit.SignerWorkerOptions{
		Observer: metrics,
	})
	spawn("audit-signer-worker", auditWorker.Run)

	// P2.3 follow-up: daily audit_log snapshot to R2/S3. Off unless
	// AUDIT_SNAPSHOT_ENABLED + endpoint/bucket/creds are set. Wrapped in
	// a leader runner so a multi-replica gateway doesn't upload N times.
	if cfg.AuditSnapshotEnabled {
		if cfg.AuditSnapshotEndpoint == "" || cfg.AuditSnapshotBucket == "" ||
			cfg.AuditSnapshotAccessKey == "" || cfg.AuditSnapshotSecretKey == "" {
			logger.Warn("audit snapshot enabled but S3 credentials/endpoint missing — worker disabled")
		} else {
			s3 := audit.NewS3Client(
				cfg.AuditSnapshotEndpoint, cfg.AuditSnapshotBucket, cfg.AuditSnapshotRegion,
				cfg.AuditSnapshotAccessKey, cfg.AuditSnapshotSecretKey,
			)
			snap := audit.NewSnapshotter(db.Pool(), s3, logger, audit.SnapshotterOptions{
				Prefix:   cfg.AuditSnapshotPrefix,
				Observer: metrics,
			})
			spawn("audit-snapshot-leader", (&leader.Runner{
				Pool:   db.Pool(),
				Name:   "audit-snapshot",
				LockID: leader.AuditSnapshotLockID,
				Func:   snap.Run,
				Logger: logger,
			}).Start)
			logger.Info("audit snapshot worker enabled",
				"endpoint", cfg.AuditSnapshotEndpoint, "bucket", cfg.AuditSnapshotBucket)
		}
	}

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
	//
	// P0.4: the listener fans Solana events into webhook publish — running
	// it on every replica would duplicate every external webhook. Run only
	// on the elected leader so a multi-replica gateway still fires each
	// event exactly once.
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
		spawn("solana-listener-leader", (&leader.Runner{
			Pool:   db.Pool(),
			Name:   "solana-listener",
			LockID: leader.SolanaListenerLockID,
			Func:   listener.Start,
			Logger: logger,
		}).Start)
	} else {
		logger.Info("solana listener disabled — set SOLANA_RPC_URL and at least one program ID")
	}

	// --- Future-Sign trigger watcher (Sprint 4 — off-chain) ---
	//
	// P0.4: the watcher spawns three internal loops that each complete a
	// future-sign on schedule. Two replicas would each try to complete the
	// same trigger — duplicate sign + duplicate gas. Wrap in leader so
	// exactly one replica drives the watcher loops.
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
		// fsWatcher.Start spawns goroutines and returns immediately. The
		// leader Func must block until ctx is cancelled, so we Start and
		// then wait on ctx — when leadership ends the inner goroutines
		// observe ctx.Done() and exit.
		spawn("future-sign-leader", (&leader.Runner{
			Pool:   db.Pool(),
			Name:   "future-sign",
			LockID: leader.FutureSignWatcherLockID,
			Func: func(ctx context.Context) {
				fsWatcher.Start(ctx)
				<-ctx.Done()
			},
			Logger: logger,
		}).Start)
		fsWatcherRunning = true
		logger.Info("future-sign watcher running (leader-elected)",
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

	// --- RT2: Risk assessment layer (always available as advisory) ---
	// Evaluates transaction risk before signing based on destination, history,
	// on-chain freshness, and custom denylist/allowlist. Integrates with
	// ika-backend simulation for digest verification. Advisory-only: never blocks.
	// Opt-in per-request via raw_transaction presence in challenge/submit.
	if policyV3Svc != nil {
		// Instantiate the actual risk.Service with registered sources
		// (blocklist, tenant denylist/allowlist, destination history).
		// OnchainFreshness is deferred to RT4 (requires per-chain RPC clients).

		// Adapter: converts between store.Store and risk package interfaces.
		storeAdapter := policy.NewStoreAdapter(db)

		// Create and register pluggable risk sources.
		sources := policy.NewRiskRegistry()
		sources.Register(policy.NewBlocklistSource(storeAdapter))
		sources.Register(policy.NewTenantDenylistSource(storeAdapter))
		sources.Register(policy.NewTenantAllowlistSource(storeAdapter))
		sources.Register(policy.NewDestHistorySource(storeAdapter))
		// NOTE: OnchainFreshnessSource deferred to RT4 (requires RPC client + chain detection).

		// Create the core risk.Service with sources.
		internalRiskSvc := policy.NewRiskService(storeAdapter, logger)
		// Register all sources.
		for _, src := range sources.All() {
			internalRiskSvc.RegisterSource(src)
		}

		// Create the config service.
		internalRiskConfigSvc := policy.NewRiskConfigService(storeAdapter)

		// Wrap both in policy layer adapters (map[string]interface{} ↔ typed).
		riskSvc := policy.NewRiskServiceAdapter(internalRiskSvc)
		riskConfigSvc := policy.NewRiskConfigServiceAdapter(internalRiskConfigSvc)

		// Create the internal ika-backend HTTP client with circuit breaker.
		// Only instantiate if IkaUpstreamURL and InternalAPIKey are both set
		// (for digest verification). Without them, calldata/simulation are unavailable,
		// but risk evaluation of destination still works.
		var ikaClient policy.IkaSimulateClient
		if cfg.IkaUpstreamURL != "" && cfg.InternalAPIKey != "" {
			ikaClientSettings := gobreaker.Settings{
				Name:        "ika-simulate",
				MaxRequests: 1,
				Interval:    60 * time.Second,
				Timeout:     30 * time.Second,
				ReadyToTrip: func(c gobreaker.Counts) bool {
					if c.ConsecutiveFailures >= 5 {
						return true
					}
					if c.Requests >= 20 {
						ratio := float64(c.TotalFailures) / float64(c.Requests)
						return ratio >= 0.5
					}
					return false
				},
			}

			ic, err := policy.NewIkaSimulateClient(
				cfg.IkaUpstreamURL,
				cfg.InternalAPIKey,
				ikaClientSettings,
				15*time.Second, // timeout for simulate calls
			)
			if err != nil {
				logger.Warn("RT2: ika-backend client init failed (continuing without digest verification)", "err", err)
			} else {
				ikaClient = ic
			}
			logger.Info("RT2: risk assessment layer with digest verification enabled",
				"ika_url", cfg.IkaUpstreamURL,
				"sources", len(sources.All()))
		} else {
			logger.Info("RT2: risk assessment layer enabled (digest verification disabled — set IKA_UPSTREAM_URL + INTERNAL_API_KEY to enable)",
				"sources", len(sources.All()))
		}

		// Wire all three into policyV3Svc.
		policyV3Svc.WithRiskService(riskSvc)
		policyV3Svc.WithRiskConfigService(riskConfigSvc)
		if ikaClient != nil {
			policyV3Svc.WithIkaSimulateClient(ikaClient)
		}
	}

	// --- Refresh-on-sign (optional) ---
	// When the Pyth adapter program id is configured, the gas-sponsored
	// request_signature prepends a refresh_feed for each sponsored FeedCache it
	// reads, so the price is fresh at the signing moment. Uses the policy gas
	// sponsor as fee payer; refresh_feed is permissionless, so no authority key
	// is needed. Independent of the managed crank below (either/both can run).
	if policyV3Svc != nil && cfg.PythAdapterProgramID != "" {
		adapterPID, err := solana.PublicKeyFromBase58(cfg.PythAdapterProgramID)
		if err != nil {
			logger.Error("refresh-on-sign: invalid PYTH_ADAPTER_PROGRAM_ID", "err", err)
			os.Exit(1)
		}
		refresher, err := oraclerelay.NewRefresher(adapterPID, cfg.PythAdapterCluster, oraclerelay.NewStore(db.Pool()))
		if err != nil {
			logger.Error("refresh-on-sign: refresher init failed", "err", err)
			os.Exit(1)
		}
		policyV3Svc.WithOracleRefresher(refresher)
		logger.Info("policy-engine v3 refresh-on-sign enabled", "adapter", adapterPID.String())
	}

	// --- Pyth adapter oracle relay (optional, leader-elected crank) ---
	// Refreshes the on-chain FeedCache PDAs so policy-engine KIND_ORACLE rules
	// see fresh prices. Needs the adapter program id + authority key + RPC.
	// The Service is also handed to the HTTP server for the `/v1/oracle/*`
	// admin routes; the crank loop itself runs only on the elected leader.
	var oracleRelaySvc *oraclerelay.Service
	if cfg.PythAdapterProgramID != "" && cfg.PythAdapterAuthorityKey != "" && cfg.SolanaRPCURL != "" {
		adapterPID, err := solana.PublicKeyFromBase58(cfg.PythAdapterProgramID)
		if err != nil {
			logger.Error("pyth adapter: invalid PYTH_ADAPTER_PROGRAM_ID", "err", err)
			os.Exit(1)
		}
		relayRPC := rpc.New(cfg.SolanaRPCURL)
		relaySigner, err := gasponsor.New(cfg.PythAdapterAuthorityKey, relayRPC)
		if err != nil {
			logger.Error("pyth adapter: authority key init failed", "err", err)
			os.Exit(1)
		}
		var seeds []oraclerelay.FeedSeed
		if cfg.PythAdapterFeedsJSON != "" {
			if err := json.Unmarshal([]byte(cfg.PythAdapterFeedsJSON), &seeds); err != nil {
				logger.Error("pyth adapter: invalid PYTH_ADAPTER_FEEDS json", "err", err)
				os.Exit(1)
			}
		}
		relaySvc, err := oraclerelay.NewService(oraclerelay.Options{
			ProgramID:    adapterPID,
			Cluster:      cfg.PythAdapterCluster,
			Tick:         cfg.PythAdapterTick,
			Seeds:        seeds,
			RPC:          relayRPC,
			Signer:       relaySigner,
			Store:        oraclerelay.NewStore(db.Pool()),
			HermesURL:    cfg.PythHermesURL,
			Logger:       logger,
			CrankEnabled: cfg.PythAdapterCrankEnabled,
			Metrics:      metrics,
		})
		if err != nil {
			logger.Error("pyth adapter: oracle relay init failed", "err", err)
			os.Exit(1)
		}
		oracleRelaySvc = relaySvc
		spawn("oracle-relay-leader", (&leader.Runner{
			Pool:   db.Pool(),
			Name:   "oracle-relay",
			LockID: leader.OracleRelayLockID,
			Func:   func(ctx context.Context) { relaySvc.Start(ctx) },
			Logger: logger,
		}).Start)
		logger.Info("pyth adapter oracle relay running (leader-elected)",
			"program_id", adapterPID.String(), "cluster", cfg.PythAdapterCluster,
			"authority", relaySigner.PublicKey().String(), "feeds", len(seeds),
			"crank_enabled", cfg.PythAdapterCrankEnabled)
	} else {
		logger.Info("pyth adapter oracle relay disabled — set PYTH_ADAPTER_PROGRAM_ID, PYTH_ADAPTER_AUTHORITY_KEY and SOLANA_RPC_URL to enable")
	}

	// --- Oracle price-trigger monitor (F7.5, leader-elected managed keeper) ---
	// Reads live Pyth prices from Hermes (off-chain, free) and fires the
	// pre-built request_signature (gas-sponsored, refresh-on-sign) when a
	// trigger's band holds. The on-chain dispatch re-validates the real price,
	// so the monitor is an untrusted trigger — it can never forge a signature.
	// Needs the policy service as the firer (with a gas sponsor + RPC). The
	// store is always created so /v1/oracle/triggers is mounted; only the
	// watcher is gated (capabilities reports oracleMonitor only when running).
	omStore := oraclemonitor.NewStore(db.Pool())
	omRunning := false
	if policyV3Svc != nil && cfg.GasSponsorKeypairJSON != "" && cfg.SolanaRPCURL != "" {
		omWatcher := oraclemonitor.NewWatcher(oraclemonitor.WatcherOptions{
			Store:     omStore,
			Prices:    oraclemonitor.NewHermesClient(cfg.PythHermesURL),
			Firer:     policyV3Svc,
			Publisher: whPublisher,
			Metrics:   metrics,
			Cluster:   cfg.PythAdapterCluster,
			Tick:      cfg.OracleMonitorTick,
			Logger:    logger,
		})
		spawn("oracle-monitor-leader", (&leader.Runner{
			Pool:   db.Pool(),
			Name:   "oracle-monitor",
			LockID: leader.OracleMonitorLockID,
			Func:   func(ctx context.Context) { omWatcher.Start(ctx) },
			Logger: logger,
		}).Start)
		omRunning = true
		logger.Info("oracle price-trigger monitor running (leader-elected)",
			"cluster", cfg.PythAdapterCluster, "hermes", cfg.PythHermesURL, "tick", cfg.OracleMonitorTick)
	} else {
		logger.Info("oracle price-trigger monitor disabled — needs policy-engine + ANDROMEDA_GAS_SPONSOR_KEYPAIR + SOLANA_RPC_URL")
	}

	// Billing migrated to backend (M1 of architecture split). Gateway
	// no longer boots a Stripe service or overage worker — those live
	// in `backend/cmd/server`.

	// RISK INGEST (RT3): Periodic blocklist feed ingestion with leader election.
	// Only runs when feeds are configured via RISK_BLOCKLIST_FEEDS.
	if len(cfg.RiskBlocklistFeeds) > 0 {
		feedSources := make([]risk.FeedSource, 0, len(cfg.RiskBlocklistFeeds))
		feedURLs := make([]string, 0, len(cfg.RiskBlocklistFeeds))

		// C1: Parse feed config using pipe (|) separator to avoid collision with https:// scheme.
		// Format: "https://example.com/list.json|metamask-phishing|phishing|Apache-2.0"
		for _, feedSpec := range cfg.RiskBlocklistFeeds {
			parts := strings.Split(feedSpec, "|")
			if len(parts) < 3 {
				logger.Warn("risk feed format invalid, skipping",
					"feed", feedSpec, "expected", "url|source|category|[license]")
				continue
			}

			url := strings.TrimSpace(parts[0])
			source := strings.TrimSpace(parts[1])
			category := strings.TrimSpace(parts[2])
			license := ""
			if len(parts) > 3 {
				license = strings.TrimSpace(parts[3])
			}

			if url == "" || source == "" || category == "" {
				logger.Warn("risk feed has empty fields, skipping", "feed", feedSpec)
				continue
			}

			feedSources = append(feedSources, risk.FeedSource{
				URL:      url,
				Source:   source,
				Category: category,
				License:  license,
			})
			feedURLs = append(feedURLs, url)
		}

		if len(feedSources) > 0 {
			// C2: Seed feeds in database at boot so ClaimDueFeedRuns has something to work with
			if err := db.SeedFeedRuns(bootCtx, feedURLs); err != nil {
				logger.Error("seed risk feeds failed", "err", err)
			} else {
				logger.Info("risk feeds seeded", "count", len(feedURLs))
			}

			ingestor := risk.NewIngestor(risk.IngestorOptions{
				Store:                     db,
				FeedRuns:                  db,
				Logger:                    logger,
				URLGuard:                  urlGuard,
				Feeds:                     feedSources,
				TickInterval:              cfg.RiskIngestTickSec,
				HTTPTimeout:               30 * time.Second,
				VariationThresholdPercent: 30,
			})

			// H1 + H5: Wrap ingestor in leader election to ensure single-replica ingestion
			// and proper graceful shutdown via rootCtx.
			spawn("risk-ingestor-leader", (&leader.Runner{
				Pool:   db.Pool(),
				Name:   "risk-ingestor",
				LockID: leader.RiskIngestorLockID,
				Func: func(ctx context.Context) {
					ingestor.Start(ctx)
					<-ctx.Done()
				},
				Logger: logger,
			}).Start)
			logger.Info("risk blocklist ingestor running (leader-elected)",
				"feeds", len(feedSources), "tick", cfg.RiskIngestTickSec)
		}
	}

	// --- HTTP server ---
	srv := api.NewServer(api.Deps{
		Config:                   cfg,
		Store:                    db,
		Limiter:                  limiter,
		Pricer:                   pricer,
		Usage:                    recorder,
		Upstreams:                ups,
		Redis:                    rdb,
		Audit:                    auditRec,
		WebhookStore:             whStore,
		PolicyV3Service:          policyV3Svc,
		PolicySubscriptions:      policySubsStore,
		OracleRelay:              oracleRelaySvc,
		OracleMonitorStore:       omStore,
		OracleMonitorRunning:     omRunning,
		FutureSignStore:          fsStore,
		FutureSignWatcherRunning: fsWatcherRunning,
		Metrics:                  metrics,
		MetricsHandler:           metricsHandler,
		URLGuard:                 urlGuard,
		Logger:                   logger,
	})

	// Background scraper that pushes runtime gauges (usage buffer +
	// breaker state + webhook DLQ depth + pgxpool + webhook backlog)
	// into Prometheus collectors every 15s. Counters update inline from
	// request handlers; gauges only need a periodic refresh.
	spawn("metrics-scraper", func(ctx context.Context) {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		sample := func() {
			updateGauges(ctx, metrics, recorder, ups, whStore, db)
			// Armed price triggers (F7.5 monitor observability).
			if n, err := omStore.CountArmed(ctx, cfg.PythAdapterCluster); err == nil {
				metrics.SetOracleArmedTriggers(n)
			}
		}
		sample()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sample()
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
// gauges (buffer depth, breaker state, DLQ depth, pool stats, webhook
// backlog) need a polling source.
func updateGauges(ctx context.Context, m *gwmetrics.Metrics, recorder *usage.Recorder, ups *upstream.Registry, whStore *webhooks.Store, db store.Store) {
	if recorder != nil {
		m.UsageBufferDepth.Set(float64(recorder.BufferDepth()))
	}
	for _, name := range []string{"ika", "encrypt"} {
		t := ups.Get(name)
		state := stateToFloat(t.State())
		m.CircuitBreakerState.WithLabelValues(name).Set(state)
	}
	if whStore != nil {
		whCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if depth, err := whStore.CountDLQ(whCtx); err == nil {
			m.WebhookDLQDepth.Set(float64(depth))
		}
		if snap, err := whStore.BacklogSnapshot(whCtx); err == nil {
			m.WebhookPendingCount.Set(float64(snap.Pending))
			m.WebhookInFlightCount.Set(float64(snap.InFlight))
			m.WebhookOldestPendingSeconds.Set(snap.OldestPendingAgeSec)
			m.WebhookOldestInFlightSeconds.Set(snap.OldestInFlightAgeSec)
		}
	}
	// pgxpool stats — pool.Stat() is cheap (atomic counters); no DB round-trip.
	if db != nil {
		if pool := db.Pool(); pool != nil {
			s := pool.Stat()
			m.DBPoolAcquired.Set(float64(s.AcquiredConns()))
			m.DBPoolIdle.Set(float64(s.IdleConns()))
			m.DBPoolTotal.Set(float64(s.TotalConns()))
			m.DBPoolMax.Set(float64(s.MaxConns()))
			m.DBPoolNewConnsTotal.Set(float64(s.NewConnsCount()))
			m.DBPoolAcquireCount.Set(float64(s.AcquireCount()))
			m.DBPoolEmptyAcquireTotal.Set(float64(s.EmptyAcquireCount()))
			m.DBPoolCanceledAcquireTotal.Set(float64(s.CanceledAcquireCount()))
			m.DBPoolAcquireWaitSeconds.Set(s.AcquireDuration().Seconds())
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

// safeGet safely accesses a slice element by index with a default fallback.
func safeGet(s []string, idx int, def string) string {
	if idx < len(s) {
		return s[idx]
	}
	return def
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
