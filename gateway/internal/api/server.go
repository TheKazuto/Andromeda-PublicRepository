package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/auth"
	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/futuresign"
	"github.com/shinkalabs/andromeda-gateway/internal/idempotency"
	"github.com/shinkalabs/andromeda-gateway/internal/mcp"
	gwmetrics "github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
	"github.com/shinkalabs/andromeda-gateway/internal/policies"
	"github.com/shinkalabs/andromeda-gateway/internal/pricing"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/routes"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
	"github.com/shinkalabs/andromeda-gateway/internal/usage"
	"github.com/shinkalabs/andromeda-gateway/internal/webhooks"
)

// Server bundles the dependencies the HTTP layer needs.
type Server struct {
	cfg              *config.Config
	store            store.Store
	limiter          ratelimit.Limiter
	pricer           *pricing.Pricer
	usage            *usage.Recorder
	upstreams        *upstream.Registry
	logger           *slog.Logger
	idempotencyChain func(http.Handler) http.Handler
	auditRecorder    *audit.Recorder
	auditReader      *audit.Reader
	webhookStore     *webhooks.Store
	policyService    *policies.Service
	futureSignStore  *futuresign.Store
	mcpTools         *mcp.ToolRegistry
	metrics          *gwmetrics.Metrics
	metricsHandler   http.Handler
	urlGuard         *netsafety.Validator

	// apiKeyTouched debounces api_keys.last_used_at writes — see
	// maybeTouchAPIKey. Keyed by api_key id, value is the last touch time.
	apiKeyTouched sync.Map
}

type Deps struct {
	Config              *config.Config
	Store               store.Store
	Limiter             ratelimit.Limiter
	Pricer              *pricing.Pricer
	Usage               *usage.Recorder
	Upstreams           *upstream.Registry
	Redis               *redis.Client
	Audit               *audit.Recorder
	WebhookStore        *webhooks.Store
	PolicyService       *policies.Service
	PolicySubscriptions *policies.SubscriptionsStore
	FutureSignStore     *futuresign.Store
	Metrics             *gwmetrics.Metrics
	MetricsHandler      http.Handler
	// URLGuard is the SSRF validator used for tenant-supplied webhook /
	// future-sign callback URLs. nil → a ModeProduction guard.
	URLGuard *netsafety.Validator
	Logger   *slog.Logger
}

func NewServer(d Deps) *Server {
	idemOpts := idempotency.MiddlewareOptions{
		Redis:           d.Redis,
		Logger:          d.Logger,
		APIKeyIDFromCtx: apiKeyIDFromRequest,
	}
	if d.Audit != nil {
		idemOpts.OnReplay = func(r *http.Request, key string, status int) {
			a := authFrom(r)
			if a == nil || a.APIKey == nil {
				return
			}
			apiKeyID, err := uuid.Parse(a.APIKey.ID)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = d.Audit.Append(ctx, audit.Event{
				APIKeyID:     apiKeyID,
				EventType:    audit.EventIdempotencyReplayed,
				ResourceType: audit.ResourceAPIKey,
				ResourceID:   a.APIKey.ID,
				Actor:        "api_key:" + a.APIKey.ID,
				Payload: map[string]any{
					"idempotency_key": key,
					"method":          r.Method,
					"path":            r.URL.Path,
					"status":          status,
				},
			})
		}
	}
	idem := idempotency.New(idemOpts)
	var reader *audit.Reader
	if d.Audit != nil {
		reader = audit.NewReader(d.Store.Pool(), d.Audit.PublicKeyBase64())
	}
	// Wire policy subscriptions so each successful init/prepare records the
	// new policy under the calling api_key. Skipped when no PolicyService.
	if d.PolicyService != nil && d.PolicySubscriptions != nil {
		d.PolicyService.WithSubscriptions(d.PolicySubscriptions, resolveAPIKeyID)
	}
	// Wire SDK artifact URLs so /v1/policies/{address}/sdk advertises real
	// tarball locations once the build-sdk GitHub Action has published them.
	if d.PolicyService != nil && d.Config != nil {
		d.PolicyService.WithSDKArtifacts(d.Config.SDKBaseURL, d.Config.SDKVersionTag)
	}
	// Wire the encrypt-backend client for Confidential Workflows. Reuses the
	// same internal-network creds the upstream registry already has.
	if d.PolicyService != nil && d.Config != nil &&
		d.Config.EncryptUpstreamURL != "" && d.Config.InternalAPIKey != "" {
		client := policies.NewHTTPConfidentialClient(d.Config.EncryptUpstreamURL, d.Config.InternalAPIKey)
		d.PolicyService.WithConfidentialClient(client)
	}
	tools := mcp.NewToolRegistry(d.Upstreams)
	if d.Logger != nil {
		d.Logger.Info("mcp tool registry ready", "tools", tools.Count())
	}

	urlGuard := d.URLGuard
	if urlGuard == nil {
		urlGuard = netsafety.New(netsafety.ModeProduction)
	}

	return &Server{
		cfg:              d.Config,
		store:            d.Store,
		limiter:          d.Limiter,
		pricer:           d.Pricer,
		usage:            d.Usage,
		upstreams:        d.Upstreams,
		logger:           d.Logger,
		idempotencyChain: idem,
		auditRecorder:    d.Audit,
		auditReader:      reader,
		webhookStore:     d.WebhookStore,
		policyService:    d.PolicyService,
		futureSignStore:  d.FutureSignStore,
		mcpTools:         tools,
		metrics:          d.Metrics,
		metricsHandler:   d.MetricsHandler,
		urlGuard:         urlGuard,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(trustedRealIP(s.cfg.TrustedProxyCIDRs))
	r.Use(middleware.Recoverer)
	// Cap incoming bodies before any handler sees them. http.MaxBytesReader
	// short-circuits with 413 if the client streams past the limit, so
	// downstream handlers (and the reverse-proxy) see only bounded data.
	r.Use(limitPayload(MaxRequestBytes))
	if s.metrics != nil {
		r.Use(gwmetrics.Middleware(s.metrics))
	}

	if len(s.cfg.AllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   s.cfg.AllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Api-Key"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	// ----- Health -----
	// Liveness (cheap, Railway probe). Readiness (deep, ops + LB).
	r.Get("/health", s.handleHealthLiveness)
	r.Get("/health/ready", s.handleHealthReadiness)

	// ----- OpenAPI 3.1 (public — SDK generators fetch from here) -----
	r.Get("/openapi.json", s.handleOpenAPI)

	// ----- Prometheus metrics — admin-gated -----
	if s.metricsHandler != nil {
		r.With(s.requireAdmin).Get("/metrics", s.metricsHandler.ServeHTTP)
	}

	// ----- Capabilities (public — clients use this to render the active
	// feature matrix without guessing). ------
	r.Get("/capabilities", s.handleCapabilities)

	// ----- Pricing (public — devs must be able to plan cost without an
	// API key). Cached at the edge (Cache-Control: public, max-age=60).
	// /v1/pricing/plans moved to backend in M3 (product surface). ------
	r.Get("/v1/pricing", s.handlePricingCatalog)
	r.Post("/v1/pricing/estimate", s.handlePricingEstimate)

	// ----- Customer endpoints moved to backend (M3 of architecture split). -----
	// /v1/me/balance, /v1/me/usage, /v1/pricing/plans, /v1/gifts/preview,
	// /v1/gifts/redeem now live on the backend service.

	// ----- Billing moved to backend (M1 of architecture split). -----
	// Dashboard hits backend/v1/billing/* directly. The Stripe webhook
	// lives at backend/v1/billing/stripe/webhook now.

	// ----- Public proxied API -----
	for _, route := range routes.All {
		s.registerProxyRoute(r, route)
	}

	// ----- Webhooks (per-tenant, behind API key) -----
	if s.webhookStore != nil {
		r.Group(func(sub chi.Router) {
			sub.Use(s.requireAPIKey)
			sub.Use(s.requireScope(auth.ScopeAdmin))
			sub.Use(s.requireSubscription)
			sub.Use(s.applyRateLimitFor(routes.RateClassTx))
			// Idempotency on POST/PATCH/DELETE — protects accidental
			// duplicates of webhook endpoint mutations on retry.
			sub.Use(s.idempotencyChain)
			sub.Use(s.chargeQuota("gateway.webhooks.admin"))
			opts := webhooks.RouteOptions{
				Store:     s.webhookStore,
				ResolveID: resolveAPIKeyID,
				URLGuard:  s.urlGuard,
			}
			if s.auditRecorder != nil {
				opts.Audit = &webhookAuditBridge{rec: s.auditRecorder}
			}
			webhooks.MountRoutes(sub, opts)
		})
	}

	// ----- Audit log (per-tenant, behind API key) -----
	if s.auditReader != nil {
		r.Group(func(sub chi.Router) {
			sub.Use(s.requireAPIKey)
			sub.Use(s.requireScope(auth.ScopeAdmin))
			sub.Use(s.requireSubscription)
			sub.Use(s.applyRateLimitFor(routes.RateClassRead))
			sub.Use(s.chargeQuota("gateway.audit.read"))
			s.auditReader.MountRoutes(sub, resolveAPIKeyID)
		})
	}

	// ----- Policy templates (Sprint 3) -----
	if s.policyService != nil {
		r.Group(func(sub chi.Router) {
			sub.Use(s.requireAPIKey)
			sub.Use(s.requireScope(auth.ScopeAdmin))
			sub.Use(s.requireSubscription)
			sub.Use(s.applyRateLimitFor(routes.RateClassTx))
			sub.Use(s.chargeQuota("gateway.policies.admin"))
			s.policyService.MountRoutes(sub)
			s.policyService.MountSDKRoute(sub)
		})
	}

	// ----- Future-Sign triggers (Sprint 4) -----
	if s.futureSignStore != nil {
		r.Group(func(sub chi.Router) {
			sub.Use(s.requireAPIKey)
			sub.Use(s.requireScope(auth.ScopeAdmin))
			sub.Use(s.requireSubscription)
			sub.Use(s.applyRateLimitFor(routes.RateClassTx))
			sub.Use(s.idempotencyChain)
			sub.Use(s.chargeQuota("gateway.future-sign.admin"))
			fsOpts := futuresign.RouteOptions{
				Store:     s.futureSignStore,
				ResolveID: resolveAPIKeyID,
				URLGuard:  s.urlGuard,
			}
			if s.auditRecorder != nil {
				fsOpts.Audit = &futureSignAuditBridge{rec: s.auditRecorder}
			}
			futuresign.MountRoutes(sub, fsOpts)
		})
	}

	// ----- MCP -----
	// Per-tool charging happens INSIDE the handler now — the charger
	// looks up the cost for the named tool (matches REST request_costs)
	// and charges/refunds via ConsumeTokensV2/RefundTokensV2. The
	// outer middleware no longer charges a flat mcp.tool.call fee.
	//
	// Idempotency at the HTTP level still applies (same body + same
	// Idempotency-Key header replays the response).
	mcpHandler := mcp.NewHandler(s.logger, s.mcpTools, newMCPCharger(s))
	r.Route("/mcp", func(sub chi.Router) {
		sub.Use(s.requireAPIKey)
		sub.Use(s.requireScope(auth.ScopeWrite))
		sub.Use(s.requireSubscription)
		sub.Use(s.applyRateLimitFor(routes.RateClassTx))
		sub.Use(s.idempotencyChain)
		// Carry the authenticated tenant identity into the request context
		// so the MCP tool proxy can forward it to engines as
		// X-Andromeda-User-Id (same as the REST proxy). Without it,
		// tenant-scoped routes like POST /v1/dwallet/create 401 with
		// "missing tenant identity".
		sub.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if a := authFrom(r); a != nil && a.User != nil {
					r = r.WithContext(mcp.WithTenantIdentity(r.Context(), a.User.ID))
				}
				next.ServeHTTP(w, r)
			})
		})
		sub.Handle("/", mcpHandler)
		sub.Handle("/*", mcpHandler)
	})

	// ----- /admin/* moved entirely to the backend service (M4). The
	// gateway only keeps the shared-secret guard on /metrics. -----

	return r
}

func (s *Server) registerProxyRoute(r chi.Router, route routes.Route) {
	handler := s.proxyHandler(route)
	chain := r.With(s.requireAPIKey).With(s.requireScope(route.RequiredScope()))
	if route.Idempotent {
		// Idempotency runs after auth so we can scope the key per api_key,
		// but before quota so cached replays don't double-charge tokens.
		chain = chain.With(s.idempotencyChain)
	}
	chain = chain.With(
		s.requireSubscription,
		s.applyRateLimitFor(route.EffectiveRateClass()),
		s.chargeQuota(route.Key),
	)
	chain.Method(route.Method, route.Path, handler)
}
