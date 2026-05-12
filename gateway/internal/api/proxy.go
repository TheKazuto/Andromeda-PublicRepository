package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/routes"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// proxyHandler is the terminal handler in the request chain. By the
// time it runs, the request has been authenticated, rate-limited, and
// the user's quota has been charged. We forward to the upstream and
// refund the quota if the upstream returns 5xx.
func (s *Server) proxyHandler(route routes.Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		a := authFrom(r)
		target := s.upstreams.Get(route.Upstream)
		if target == nil || target.Proxy == nil {
			writeError(w, http.StatusBadGateway, "upstream_unavailable",
				"upstream "+route.Upstream+" not configured")
			s.recordUsage(r, route.Key, http.StatusBadGateway, time.Since(started), true)
			s.refund(r)
			return
		}

		// Per-route timeout override. Heavy MPC operations need more
		// wall-clock than the global UPSTREAM_TIMEOUT — derive a child
		// context so the reverse-proxy stops at the right deadline. When
		// this deadline fires the upstream RoundTrip fails with
		// context.DeadlineExceeded (a legitimate "engine too slow"
		// failure) — distinct from context.Canceled (client went away),
		// which the ErrorHandler maps to 499.
		if route.TimeoutSeconds > 0 {
			ctx, cancel := context.WithTimeout(r.Context(),
				time.Duration(route.TimeoutSeconds)*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
		}

		// Sunset / Deprecation headers (RFC 8594). Emit before any
		// upstream interaction so even error responses carry the hint.
		if route.DeprecatedAt != "" {
			w.Header().Set("Deprecation", route.DeprecatedAt)
		}
		if route.SunsetAt != "" {
			w.Header().Set("Sunset", route.SunsetAt)
		}

		// Circuit breaker check — fast-fail with 503 when the breaker
		// is open, so callers see a quick response and we don't pile
		// load on a struggling upstream.
		if err := target.Allow(); errors.Is(err, upstream.ErrCircuitOpen) {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusServiceUnavailable, "upstream_circuit_open",
				"upstream "+route.Upstream+" temporarily unavailable")
			if s.metrics != nil {
				s.metrics.UpstreamRequestsTotal.
					WithLabelValues(route.Upstream, "circuit").Inc()
			}
			s.recordUsage(r, route.Key, http.StatusServiceUnavailable, time.Since(started), true)
			s.refund(r)
			return
		}

		// Rewrite the path to the upstream's path. chi URLParams need to
		// be inlined (e.g. /v1/dwallet/{id} -> /v1/dwallet/abc).
		upstreamPath := route.TargetPath()
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			for i, k := range rctx.URLParams.Keys {
				if i < len(rctx.URLParams.Values) {
					upstreamPath = strings.ReplaceAll(upstreamPath, "{"+k+"}", rctx.URLParams.Values[i])
				}
			}
		}
		// Strip any X-Andromeda-* the caller may have sent so it cannot
		// spoof tenant identity / routing headers, then set the ones the
		// gateway controls. The upstream-path is carried in a header the
		// reverse-proxy Rewrite consumes (and deletes).
		stripAndromedaHeaders(r.Header)
		r.Header.Set("X-Andromeda-Upstream-Path", upstreamPath)
		r.Header.Set("X-Andromeda-Request-Id", requestIDFromCtx(r))
		if a != nil && a.User != nil {
			r.Header.Set("X-Andromeda-User-Id", a.User.ID)
		}

		rec := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		target.Proxy.ServeHTTP(rec, r)

		status := rec.Status()
		if status == 0 {
			status = http.StatusOK
		}
		latency := time.Since(started)

		// 499 = the reverse-proxy ErrorHandler observed a client-cancelled
		// request (caller went away mid-flight). That is neither an
		// upstream fault nor a billable success — don't feed the breaker.
		clientClosed := status == upstream.StatusClientClosedRequest
		if !clientClosed {
			var upstreamErr error
			if status >= 500 {
				upstreamErr = errors.New("upstream 5xx")
			}
			target.MarkResult(status, upstreamErr)
		}
		if s.metrics != nil {
			s.metrics.UpstreamRequestsTotal.
				WithLabelValues(route.Upstream, metrics.StatusClass(status)).Inc()
			s.metrics.UpstreamLatency.
				WithLabelValues(route.Upstream).Observe(latency.Seconds())
		}

		// Refund policy:
		//   - 5xx from the upstream: the engine could not service it → refund.
		//   - 4xx: the caller's fault → stays charged.
		//   - 499 (client closed): only refund a read route that produced no
		//     bytes; a mutating engine call may already have taken effect, so
		//     we cannot safely refund without evidence it never landed.
		refunded := false
		switch {
		case status >= 500:
			s.refund(r)
			refunded = true
		case clientClosed && route.EffectiveRateClass() == routes.RateClassRead && rec.BytesWritten() == 0:
			s.refund(r)
			refunded = true
		}

		s.recordUsage(r, route.Key, status, latency, refunded)
	}
}

// stripAndromedaHeaders deletes every X-Andromeda-* header from h so a
// client cannot inject one the engines might trust. Case-insensitive —
// http.Header keys are canonicalised, but we compare defensively.
func stripAndromedaHeaders(h http.Header) {
	for k := range h {
		if len(k) >= len("X-Andromeda-") &&
			strings.EqualFold(k[:len("X-Andromeda-")], "X-Andromeda-") {
			h.Del(k)
		}
	}
}

func (s *Server) recordUsage(r *http.Request, routeKey string, status int, latency time.Duration, refunded bool) {
	a := authFrom(r)
	if a == nil || a.User == nil {
		return
	}
	cost := costFrom(r)
	if refunded {
		// The tokens went back to the bucket — record what was actually
		// paid (zero), not what the route would have cost.
		cost = 0
	}
	ev := store.UsageEvent{
		UserID:     a.User.ID,
		RouteKey:   routeKey,
		CostTokens: cost,
		StatusCode: status,
		LatencyMs:  int(latency.Milliseconds()),
		RequestID:  requestIDFromCtx(r),
		OccurredAt: time.Now().UTC(),
	}
	if a.APIKey != nil {
		id := a.APIKey.ID
		ev.APIKeyID = &id
	}
	if a.Subscription != nil {
		id := a.Subscription.ID
		ev.SubscriptionID = &id
	}
	s.usage.Record(ev)
}

// refund undoes the consumption charge attached to the request when an
// upstream 5xx happens. It uses the bucket-aware ConsumptionResult
// stored in context — refunds monthly and overage; credits are NOT
// refunded (schema does not track per-row credit debits — see
// store/consume.go RefundTokensV2 godoc).
func (s *Server) refund(r *http.Request) {
	a := authFrom(r)
	if a == nil || a.Subscription == nil {
		return
	}
	consumption := consumptionFrom(r)
	if consumption == nil {
		// Legacy code path (no chargeQuota was applied) — nothing to refund.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.store.RefundTokensV2(ctx, a.Subscription.ID, *consumption); err != nil {
		s.logger.Warn("refund failed",
			"err", err,
			"subscription", a.Subscription.ID,
			"from_monthly", consumption.FromMonthly,
			"from_overage", consumption.FromOverage)
	}
}
