package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// Middleware returns a chi-style middleware that records request count,
// duration and in-flight count. Route label uses the chi route pattern
// (e.g. "/v1/dwallet/{id}") so we don't blow up cardinality with
// per-id timeseries.
func Middleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.HTTPInFlight.Inc()
			rec := &statusRecorder{ResponseWriter: w, status: 200}

			next.ServeHTTP(rec, r)

			m.HTTPInFlight.Dec()
			route := routeOf(r)
			m.HTTPRequestsTotal.
				WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).
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

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}
