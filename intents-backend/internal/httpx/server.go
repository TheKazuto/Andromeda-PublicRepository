package httpx

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RouterOptions wires the shared HTTP layer.
type RouterOptions struct {
	Logger         *slog.Logger
	InternalAPIKey string
	Readiness      ReadinessFunc
	// MetricsRegistry, when set, exposes /metrics.
	MetricsRegistry *prometheus.Registry
	// Mount registers the internal (X-Internal-Key) routes on the given router.
	Mount func(r chi.Router)
}

// NewRouter builds the chi mux: health probes are open; everything mounted via
// Mount sits behind the internal-key guard. Timeout is generous (LI.FI + RPC
// can take a few seconds) but bounded so goroutines never leak under load.
func NewRouter(opts RouterOptions) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(Recoverer(opts.Logger))
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/health", Health)
	r.Get("/health/ready", Ready(opts.Readiness))

	if opts.MetricsRegistry != nil {
		r.Handle("/metrics", promhttp.HandlerFor(opts.MetricsRegistry, promhttp.HandlerOpts{}))
	}

	r.Group(func(sub chi.Router) {
		sub.Use(RequireInternalKey(opts.InternalAPIKey))
		if opts.Mount != nil {
			opts.Mount(sub)
		}
	})

	return r
}
