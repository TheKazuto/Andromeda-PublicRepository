package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// Middleware returns a chi-style middleware that records request count,
// duration and in-flight count. Route label uses the chi route pattern
// (e.g. "/v1/dwallet/{id}") so we don't blow up cardinality with
// per-id timeseries.
//
// The response writer is wrapped with chi's WrapResponseWriter, which
// exposes Status()/BytesWritten() while still delegating http.Flusher,
// http.Hijacker and http.Pusher to the underlying writer. That delegation
// is what keeps SSE responses (GET /mcp) working — a bare struct wrapper
// would hide Flush() and break streaming.
func Middleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.HTTPInFlight.Inc()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			m.HTTPInFlight.Dec()
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			route := routeOf(r)
			m.HTTPRequestsTotal.
				WithLabelValues(r.Method, route, strconv.Itoa(status)).
				Inc()
			m.HTTPRequestDuration.
				WithLabelValues(r.Method, route).
				Observe(time.Since(start).Seconds())
		})
	}
}

// routeOf returns the chi route pattern for the current request, with
// fallback to the raw path when the request did not match a chi route
// (e.g. /metrics, /health). Bounded cardinality is critical for Prom.
func routeOf(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pat := rctx.RoutePattern(); pat != "" {
			return pat
		}
	}
	return r.URL.Path
}
