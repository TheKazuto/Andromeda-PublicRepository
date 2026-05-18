package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// Middleware returns a chi-compatible middleware that records request
// latency, count and in-flight gauge. The route label is the chi route
// pattern when available, falling back to `unknown` so cardinality stays
// bounded.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		m.HTTPInFlight.Inc()
		defer m.HTTPInFlight.Dec()

		ww := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)

		route := "unknown"
		if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
			route = rctx.RoutePattern()
		}
		elapsed := time.Since(started).Seconds()
		m.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(elapsed)
		m.HTTPRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(ww.status)).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
