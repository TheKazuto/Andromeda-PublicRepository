// Package metrics owns every Prometheus collector exposed by the gateway.
// All metrics share the namespace "gateway" so dashboards can pivot
// without per-service prefixes leaking through.
//
// Collectors are registered on a private *prometheus.Registry rather
// than the global default so we can isolate them in tests and avoid
// accidental Go runtime metric pollution under /metrics. The global
// default still receives the runtime collectors via NewGoCollector,
// added explicitly below for visibility.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles every collector for easy injection into the request
// chain and worker bookkeeping. All counters/gauges/histograms are
// safe for concurrent use.
type Metrics struct {
	registry *prometheus.Registry

	// HTTP — emitted by the request middleware.
	HTTPRequestsTotal   *prometheus.CounterVec   // labels: method, route, status
	HTTPRequestDuration *prometheus.HistogramVec // labels: method, route
	HTTPInFlight        prometheus.Gauge

	// Quota & rate-limit — emitted by chargeQuota / applyRateLimitFor.
	QuotaConsumedTotal  *prometheus.CounterVec // labels: plan, bucket (credits|monthly|overage)
	QuotaExceededTotal  *prometheus.CounterVec // labels: plan
	RateLimitBlockedTotal *prometheus.CounterVec // labels: class (read|tx)

	// Upstream — emitted by the proxy handler.
	UpstreamRequestsTotal *prometheus.CounterVec // labels: upstream, status_class
	UpstreamLatency       *prometheus.HistogramVec // labels: upstream
	CircuitBreakerState   *prometheus.GaugeVec   // labels: upstream  (0=closed,1=open,2=half-open)
	CircuitBreakerTripsTotal *prometheus.CounterVec // labels: upstream

	// Usage recorder backpressure — gauges scraped from the recorder.
	UsageBufferDepth     prometheus.Gauge
	UsageBufferDrops     prometheus.Counter

	// Worker ticks — diagnostics for slow workers.
	WorkerTickTotal *prometheus.CounterVec // labels: worker, outcome

	// Webhooks: DLQ depth (gauge sampled periodically) and on-chain
	// listener drops (counter incremented inline by the rate limiter).
	WebhookDLQDepth      prometheus.Gauge
	ListenerEventsDropped *prometheus.CounterVec // labels: reason
}

// New builds and registers every collector. Returns the Metrics bundle
// and the http.Handler that serves /metrics.
func New() (*Metrics, http.Handler) {
	reg := prometheus.NewRegistry()
	// Register Go runtime + process metrics so /metrics looks normal to
	// Prometheus scrapers. Strip the build_info if you want a tighter set.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{registry: reg}

	m.HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "HTTP requests by method, route, and status.",
		}, []string{"method", "route", "status"})
	m.HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gateway",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "End-to-end gateway latency (excluding upstream wait).",
			// Reasonable buckets for an API gateway in front of MPC engines.
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"method", "route"})
	m.HTTPInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "http",
		Name:      "in_flight",
		Help:      "HTTP requests currently being processed.",
	})

	m.QuotaConsumedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "quota",
			Name:      "consumed_total",
			Help:      "Tokens consumed by plan and bucket (credits/monthly/overage).",
		}, []string{"plan", "bucket"})
	m.QuotaExceededTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "quota",
			Name:      "exceeded_total",
			Help:      "402 quota_exceeded responses by plan.",
		}, []string{"plan"})

	m.RateLimitBlockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "rate_limit",
			Name:      "blocked_total",
			Help:      "429 rate_limited responses by bucket class.",
		}, []string{"class"})

	m.UpstreamRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "upstream",
			Name:      "requests_total",
			Help:      "Calls forwarded to an upstream by name and status class (2xx/4xx/5xx/error).",
		}, []string{"upstream", "status_class"})
	m.UpstreamLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gateway",
			Subsystem: "upstream",
			Name:      "latency_seconds",
			Help:      "Wall-clock latency for upstream calls.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"upstream"})
	m.CircuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gateway",
			Subsystem: "circuit",
			Name:      "state",
			Help:      "Circuit-breaker state per upstream (0=closed, 1=open, 2=half-open).",
		}, []string{"upstream"})
	m.CircuitBreakerTripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "circuit",
			Name:      "trips_total",
			Help:      "Cumulative count of circuit-breaker open transitions per upstream.",
		}, []string{"upstream"})

	m.UsageBufferDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "usage_buffer",
		Name:      "depth",
		Help:      "Queued usage events waiting to be flushed.",
	})
	m.UsageBufferDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway",
		Subsystem: "usage_buffer",
		Name:      "drops_total",
		Help:      "Cumulative usage events discarded because the buffer was full.",
	})

	m.WorkerTickTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "worker",
			Name:      "tick_total",
			Help:      "Background worker ticks by name and outcome (ok/error).",
		}, []string{"worker", "outcome"})

	m.WebhookDLQDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "dlq_depth",
		Help:      "Webhook deliveries currently in dead_letter status.",
	})
	m.ListenerEventsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "listener",
			Name:      "events_dropped_total",
			Help:      "On-chain events dropped before publish (rate_limit / no_tenant / parse_error).",
		}, []string{"reason"})

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.HTTPInFlight,
		m.QuotaConsumedTotal,
		m.QuotaExceededTotal,
		m.RateLimitBlockedTotal,
		m.UpstreamRequestsTotal,
		m.UpstreamLatency,
		m.CircuitBreakerState,
		m.CircuitBreakerTripsTotal,
		m.UsageBufferDepth,
		m.UsageBufferDrops,
		m.WorkerTickTotal,
		m.WebhookDLQDepth,
		m.ListenerEventsDropped,
	)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	return m, handler
}

// Registry exposes the underlying Prometheus registry for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// StatusClass converts an HTTP status into a coarse class label
// (2xx/3xx/4xx/5xx). 0 → "error" (network failure, no response).
func StatusClass(status int) string {
	switch {
	case status == 0:
		return "error"
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
