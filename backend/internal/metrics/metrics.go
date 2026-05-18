// Package metrics owns every Prometheus collector exposed by the backend.
// All collectors share the namespace "backend" so dashboards can pivot
// without per-service prefixes leaking through.
//
// Surface is intentionally minimal — backend is the product API (auth,
// API keys, billing, usage). Heavier instrumentation lives in the gateway
// (multi-tenant hot path) and the Node engines (signing/encryption).
// Phase 0 of the robustness plan calls for /metrics + pgxpool stats +
// rate-limit/worker counters so the operator can right-size the pool and
// detect runaway auth bursts before they cascade.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry *prometheus.Registry

	// HTTP — emitted by the request middleware.
	HTTPRequestsTotal   *prometheus.CounterVec   // labels: method, route, status
	HTTPRequestDuration *prometheus.HistogramVec // labels: method, route
	HTTPInFlight        prometheus.Gauge

	// Auth rate limiter — backend's in-memory IP bucket. The robustness
	// plan P0.3 migrates this to Redis; today the counter at least
	// surfaces blocked attempts so the limiter's effectiveness is
	// observable.
	AuthRateLimitBlockedTotal *prometheus.CounterVec // labels: route

	// Workers — overage, quota, pricing, applier. Outcome is `ok` or
	// `error`; combine with a rate() to derive worker uptime.
	WorkerTickTotal *prometheus.CounterVec // labels: worker, outcome

	// Postgres pgxpool — sampled every 15s by the metrics scraper.
	DBPoolAcquired             prometheus.Gauge
	DBPoolIdle                 prometheus.Gauge
	DBPoolTotal                prometheus.Gauge
	DBPoolMax                  prometheus.Gauge
	DBPoolNewConnsTotal        prometheus.Gauge
	DBPoolAcquireCount         prometheus.Gauge
	DBPoolEmptyAcquireTotal    prometheus.Gauge
	DBPoolCanceledAcquireTotal prometheus.Gauge
	DBPoolAcquireWaitSeconds   prometheus.Gauge
}

func New() (*Metrics, http.Handler) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{registry: reg}

	m.HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "backend", Subsystem: "http", Name: "requests_total",
		Help: "HTTP requests by method, route, and status.",
	}, []string{"method", "route", "status"})

	m.HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "backend", Subsystem: "http", Name: "request_duration_seconds",
		Help:    "End-to-end backend latency.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "route"})

	m.HTTPInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "http", Name: "in_flight",
		Help: "HTTP requests currently being processed.",
	})

	m.AuthRateLimitBlockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "backend", Subsystem: "auth_rate_limit", Name: "blocked_total",
		Help: "Auth attempts blocked by the per-IP rate limiter, by route.",
	}, []string{"route"})

	m.WorkerTickTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "backend", Subsystem: "worker", Name: "tick_total",
		Help: "Background worker ticks by name and outcome (ok/error).",
	}, []string{"worker", "outcome"})

	m.DBPoolAcquired = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "acquired_conns",
		Help: "Postgres connections currently checked out.",
	})
	m.DBPoolIdle = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "idle_conns",
		Help: "Postgres connections currently idle.",
	})
	m.DBPoolTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "total_conns",
		Help: "Total open Postgres connections.",
	})
	m.DBPoolMax = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "max_conns",
		Help: "Configured pool ceiling (PG_MAX_CONNS).",
	})
	m.DBPoolNewConnsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "new_conns_total",
		Help: "Cumulative new connections opened.",
	})
	m.DBPoolAcquireCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "acquire_count_total",
		Help: "Cumulative successful Acquire() calls.",
	})
	m.DBPoolEmptyAcquireTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "empty_acquire_total",
		Help: "Cumulative Acquire() calls that had to wait on an empty pool.",
	})
	m.DBPoolCanceledAcquireTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "canceled_acquire_total",
		Help: "Cumulative Acquire() calls cancelled before getting a connection.",
	})
	m.DBPoolAcquireWaitSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "backend", Subsystem: "db_pool", Name: "acquire_wait_seconds_total",
		Help: "Cumulative wait time in Acquire() (seconds).",
	})

	reg.MustRegister(
		m.HTTPRequestsTotal, m.HTTPRequestDuration, m.HTTPInFlight,
		m.AuthRateLimitBlockedTotal,
		m.WorkerTickTotal,
		m.DBPoolAcquired, m.DBPoolIdle, m.DBPoolTotal, m.DBPoolMax,
		m.DBPoolNewConnsTotal, m.DBPoolAcquireCount,
		m.DBPoolEmptyAcquireTotal, m.DBPoolCanceledAcquireTotal,
		m.DBPoolAcquireWaitSeconds,
	)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true})
	return m, handler
}

func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// StatusClass converts an HTTP status into a coarse class label.
func StatusClass(status int) string {
	switch {
	case status == 0:
		return "error"
	case status == 499:
		return "client_closed"
	case status < 200:
		return "1xx"
	case status < 300:
		return "2xx"
	case status < 400:
		return "3xx"
	case status < 500:
		return "4xx"
	default:
		return "5xx"
	}
}
