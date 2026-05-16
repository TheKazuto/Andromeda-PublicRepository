package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
	"github.com/shinkalabs/andromeda-gateway/internal/mcp"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/routes"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

// apiKeyTouchInterval is the debounce window for last_used_at writes. A
// busy API key triggers at most one UPDATE per window instead of one per
// request, which keeps the connection pool from drowning under load.
const apiKeyTouchInterval = time.Minute

// requireAPIKey authenticates the X-Api-Key / Authorization Bearer header
// and attaches the user, key and active subscription to the context.
// Also enforces the per-key IP allowlist when configured.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := auth.ExtractAPIKey(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "missing_api_key", "missing API key")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		bundle, err := s.store.AuthenticateAPIKey(ctx, auth.Hash(raw))
		switch {
		case err == nil:
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrKeyRevoked):
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "invalid API key")
			return
		default:
			s.logger.Error("api key lookup failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}

		// IP allowlist check — trustedRealIP populates r.RemoteAddr from
		// X-Forwarded-For when the peer is a trusted proxy. In production
		// the gateway sits behind the Railway edge proxy, so without a
		// configured TRUSTED_PROXY_CIDRS the RemoteAddr is the proxy and an
		// ip_allowlist on the key cannot be matched safely — reject
		// explicitly instead of locking the key out against the proxy IP.
		if len(bundle.APIKey.IPAllowlist) > 0 &&
			s.cfg.Env == "production" && len(s.cfg.TrustedProxyCIDRs) == 0 {
			writeError(w, http.StatusForbidden, "ip_allowlist_unsupported",
				"this API key has an IP allowlist but the gateway is not configured "+
					"with TRUSTED_PROXY_CIDRS — the caller IP cannot be verified")
			return
		}
		if !auth.MatchesIPAllowlist(bundle.APIKey.IPAllowlist, callerIP(r)) {
			writeError(w, http.StatusForbidden, "ip_not_allowed",
				"caller IP is not on this API key's allowlist")
			return
		}

		// Origin allowlist check — only meaningful for browser callers
		// (server-side requests have no Origin header and pass through).
		if !auth.MatchesOriginAllowlist(bundle.APIKey.AllowedOrigins, r.Header.Get("Origin")) {
			writeError(w, http.StatusForbidden, "origin_not_allowed",
				"request Origin is not on this API key's allowlist")
			return
		}

		s.maybeTouchAPIKey(r, bundle.APIKey.ID)

		next.ServeHTTP(w, withAuth(r, &authedRequest{
			User:         bundle.User,
			APIKey:       bundle.APIKey,
			Subscription: bundle.Subscription,
		}))
	})
}

// maybeTouchAPIKey updates api_keys.last_used_at asynchronously, but at
// most once per apiKeyTouchInterval per key. The DB write runs on a
// context that survives the request returning (so it actually lands) but
// is bounded by a short timeout (so it cannot leak past shutdown).
func (s *Server) maybeTouchAPIKey(r *http.Request, id string) {
	now := time.Now()
	if last, ok := s.apiKeyTouched.Load(id); ok {
		if lt, ok := last.(time.Time); ok && now.Sub(lt) < apiKeyTouchInterval {
			return
		}
	}
	s.apiKeyTouched.Store(id, now)
	// context.WithoutCancel keeps the trace/values but drops the request's
	// cancellation, so the UPDATE isn't aborted the instant ServeHTTP returns.
	parent := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		if err := s.store.TouchAPIKeyUsed(ctx, id); err != nil {
			s.logger.Debug("touch api key last_used_at failed", "err", err, "api_key", id)
		}
	}()
}

// requireScope is a middleware factory that gates a request on the
// authenticated key carrying the named scope. Wildcard ("*") and an
// empty Scopes slice both grant access (back-compat with pre-scopes
// keys). Should always run AFTER requireAPIKey.
func (s *Server) requireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := authFrom(r)
			if a == nil || a.APIKey == nil {
				writeError(w, http.StatusUnauthorized, "missing_api_key", "auth required")
				return
			}
			if !auth.HasScope(a.APIKey.Scopes, scope) {
				writeError(w, http.StatusForbidden, "scope_missing",
					"this API key does not have the required scope: "+scope)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireSubscription rejects calls from users without an active
// subscription. Authentication only proves identity; the subscription
// is what authorises access to billable upstreams.
func (s *Server) requireSubscription(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := authFrom(r)
		if a == nil || a.Subscription == nil {
			writeError(w, http.StatusForbidden, "no_active_subscription",
				"no active subscription — assign a plan to this account first")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// applyRateLimitFor is a middleware factory that returns a class-aware
// rate limiter. The class string ("read" or "tx") names the bucket; the
// limit values come from the subscription columns added in 5.1.
//
// The Redis key includes the class so each bucket has its own window:
//
//	ratelimit:<api_key_id>:<class>
//
// Plans with rps == 0 (unlimited) are passed through.
func (s *Server) applyRateLimitFor(class string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := authFrom(r)
			if a == nil || a.Subscription == nil {
				next.ServeHTTP(w, r)
				return
			}

			rps, burst := rateLimitFor(a.Subscription, class)
			err := s.limiter.Allow(r.Context(),
				a.APIKey.ID+":"+class, rps, burst)
			if errors.Is(err, ratelimit.ErrLimited) {
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-Andromeda-RateLimit-Class", class)
				if s.metrics != nil {
					s.metrics.RateLimitBlockedTotal.WithLabelValues(class).Inc()
				}
				writeError(w, http.StatusTooManyRequests, "rate_limited",
					"rate limit exceeded for class "+class)
				return
			}
			if err != nil {
				s.logger.Error("rate limiter error", "err", err, "class", class)
				writeError(w, http.StatusServiceUnavailable, "rate_limit_unavailable",
					"rate limit backend unavailable")
				return
			}
			w.Header().Set("X-Andromeda-RateLimit-Class", class)
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitFor picks the (rps, burst) pair from the subscription based
// on the class. Falls back to the legacy single-bucket fields when the
// per-class fields are zero (subscription pre-dates the 010 migration).
func rateLimitFor(sub *store.Subscription, class string) (rps, burst int) {
	switch class {
	case routes.RateClassRead:
		rps, burst = sub.ReadRPS, sub.ReadBurst
	case routes.RateClassTx:
		rps, burst = sub.TxRPS, sub.TxBurst
	default:
		rps, burst = sub.TxRPS, sub.TxBurst
	}
	if rps == 0 && burst == 0 {
		// Legacy or unset — fall back to the single-bucket value so
		// existing subscriptions still get throttled.
		return sub.RateLimitRPS, sub.RateLimitBurst
	}
	return rps, burst
}

// chargeQuota is the entry point of the billing pipeline. For the
// resolved route key, it looks up the cost in tokens, then atomically
// consumes that amount across credits → monthly → overage. The consumption
// breakdown is attached to the request so the proxy can refund per
// bucket on upstream failure.
func (s *Server) chargeQuota(routeKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// F13b: an MCP loopback call has already been charged by the
			// per-tool mcpCharger at the JSON-RPC entry point — billing
			// twice would double-debit the tenant. The marker is set only
			// by makeLoopbackHandler inside the gateway process, so it
			// cannot be spoofed by an external caller.
			if mcp.IsLoopback(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			a := authFrom(r)
			if a == nil || a.Subscription == nil {
				writeError(w, http.StatusForbidden, "no_active_subscription", "no active subscription")
				return
			}
			cost := s.pricer.Cost(routeKey)
			if cost < 1 {
				cost = 1
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			result, err := s.store.ConsumeTokensV2(ctx, a.Subscription.ID, cost)
			switch {
			case err == nil:
			case errors.Is(err, store.ErrQuotaExceeded):
				w.Header().Set("X-Andromeda-Tokens-Limit",
					strconv.FormatInt(a.Subscription.TokensLimit, 10))
				if s.metrics != nil {
					s.metrics.QuotaExceededTotal.WithLabelValues(a.Subscription.PlanCode).Inc()
				}
				writeError(w, http.StatusPaymentRequired, "quota_exceeded",
					"token quota exceeded — upgrade plan, wait for rollover, or enable overage")
				return
			default:
				s.logger.Error("consume tokens failed",
					"err", err, "user", a.User.ID, "route", routeKey)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
				return
			}

			// Headers — give the dev visibility into what bucket paid.
			w.Header().Set("X-Andromeda-Tokens-Cost", strconv.Itoa(cost))
			w.Header().Set("X-Andromeda-Tokens-Used", strconv.FormatInt(result.TokensUsed, 10))
			w.Header().Set("X-Andromeda-Tokens-Limit", strconv.FormatInt(result.Subscription.TokensLimit, 10))
			if result.FromCredits > 0 {
				w.Header().Set("X-Andromeda-Tokens-From-Credits", strconv.Itoa(result.FromCredits))
			}
			if result.FromOverage > 0 {
				w.Header().Set("X-Andromeda-Tokens-From-Overage", strconv.Itoa(result.FromOverage))
				w.Header().Set("X-Andromeda-Overage-Used", strconv.FormatInt(result.OverageUsed, 10))
			}

			if s.metrics != nil {
				if result.FromCredits > 0 {
					s.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "credits").
						Add(float64(result.FromCredits))
				}
				if result.FromMonthly > 0 {
					s.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "monthly").
						Add(float64(result.FromMonthly))
				}
				if result.FromOverage > 0 {
					s.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "overage").
						Add(float64(result.FromOverage))
				}
			}

			ctxR := withConsumption(
				withCost(withRoute(r, &routedRequest{Key: routeKey}), cost),
				result,
			)
			next.ServeHTTP(w, ctxR)
		})
	}
}

// requireAdmin gates the gateway's remaining operator endpoints (only
// /metrics today). The full admin console moved to the backend service
// in M4 — this is just a shared-secret check to keep Prometheus scraping
// behind a token.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token != "" && s.cfg.AdminToken != "" && auth.ConstantTimeEqual(token, s.cfg.AdminToken) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "admin_unauthorised", "admin token required")
	})
}

// requestIDFromCtx returns chi's request ID, or empty if missing.
func requestIDFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
		return v
	}
	return ""
}
