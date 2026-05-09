package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
	"github.com/shinkalabs/andromeda-gateway/internal/ratelimit"
	"github.com/shinkalabs/andromeda-gateway/internal/routes"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

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

		// IP allowlist check — middleware.RealIP populates r.RemoteAddr
		// upstream of this handler so we can match X-Forwarded-For too.
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

		// Touch last_used_at asynchronously — don't block the request.
		go func(id string) {
			tctx, c := context.WithTimeout(context.Background(), 2*time.Second)
			defer c()
			_ = s.store.TouchAPIKeyUsed(tctx, id)
		}(bundle.APIKey.ID)

		next.ServeHTTP(w, withAuth(r, &authedRequest{
			User:         bundle.User,
			APIKey:       bundle.APIKey,
			Subscription: bundle.Subscription,
		}))
	})
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

// callerIP picks the client IP for IP-allowlist checks. chi's RealIP
// middleware (already wired in server.go) rewrites RemoteAddr based on
// X-Forwarded-For / X-Real-IP headers, so RemoteAddr is the source of
// truth at this point.
func callerIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
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
//   ratelimit:<api_key_id>:<class>
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

// statusRecorder lets the proxy know the upstream HTTP status without
// having to read the body. Used by the usage recorder.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}
func (sr *statusRecorder) Write(b []byte) (int, error) {
	if sr.status == 0 {
		sr.status = http.StatusOK
	}
	n, err := sr.ResponseWriter.Write(b)
	sr.bytes += n
	return n, err
}

// requestIDFromCtx returns chi's request ID, or empty if missing.
func requestIDFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
		return v
	}
	return ""
}
