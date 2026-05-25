package intents

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics are the gateway-side intents collectors (namespace gateway, subsystem
// intents). Registered on the shared registry via promauto. All methods are
// nil-safe so the orchestrator/reconciler can run without metrics in tests.
type Metrics struct {
	PrepareTotal      *prometheus.CounterVec // chain_kind, result
	PrepareDuration   prometheus.Histogram
	SubmitTotal       *prometheus.CounterVec // chain_kind, result
	SubmitDuration    prometheus.Histogram
	RiskAdvisoryTotal *prometheus.CounterVec // chain_kind, level
	ReconcilerTotal   *prometheus.CounterVec // action, result
	StateTransition   *prometheus.CounterVec // from, to
	OpenAgeSeconds    *prometheus.GaugeVec   // status → age of the oldest open intent
}

// NewMetrics registers the intents collectors on reg. Returns nil when reg is
// nil (metrics disabled).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		return nil
	}
	f := promauto.With(reg)
	buckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}
	return &Metrics{
		PrepareTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "prepare_total",
			Help: "Swap prepare calls by chain kind and result (ok|error).",
		}, []string{"chain_kind", "result"}),
		PrepareDuration: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "prepare_duration_seconds",
			Help: "Swap prepare latency.", Buckets: buckets,
		}),
		SubmitTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "submit_total",
			Help: "Swap submit calls by chain kind and resulting status.",
		}, []string{"chain_kind", "result"}),
		SubmitDuration: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "submit_duration_seconds",
			Help: "Swap submit latency (one call; an ERC20 swap may take several).", Buckets: buckets,
		}),
		RiskAdvisoryTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "risk_advisory_total",
			Help: "Advisory risk evaluations by chain kind and level (none|low|medium|high|critical).",
		}, []string{"chain_kind", "level"}),
		ReconcilerTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "reconciler_total",
			Help: "Reconciler resolutions by action (expire|fail|settle) and result.",
		}, []string{"action", "result"}),
		StateTransition: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "state_transition_total",
			Help: "Intent status transitions by from→to.",
		}, []string{"from", "to"}),
		OpenAgeSeconds: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "gateway", Subsystem: "intents", Name: "open_age_seconds",
			Help: "Age of the oldest open intent per status (sampled by the reconciler).",
		}, []string{"status"}),
	}
}

func (m *Metrics) recordPrepare(chainKind, result string, seconds float64) {
	if m == nil {
		return
	}
	m.PrepareTotal.WithLabelValues(chainKind, result).Inc()
	m.PrepareDuration.Observe(seconds)
}

func (m *Metrics) recordSubmit(chainKind, result string, seconds float64) {
	if m == nil {
		return
	}
	m.SubmitTotal.WithLabelValues(chainKind, result).Inc()
	m.SubmitDuration.Observe(seconds)
}

func (m *Metrics) recordRisk(chainKind, level string) {
	if m == nil {
		return
	}
	if level == "" {
		level = "none"
	}
	m.RiskAdvisoryTotal.WithLabelValues(chainKind, level).Inc()
}

func (m *Metrics) recordReconciler(action, result string) {
	if m == nil {
		return
	}
	m.ReconcilerTotal.WithLabelValues(action, result).Inc()
}

func (m *Metrics) recordTransition(from, to string) {
	if m == nil || from == "" || to == "" {
		return
	}
	m.StateTransition.WithLabelValues(from, to).Inc()
}

func (m *Metrics) setOpenAges(ages map[string]float64) {
	if m == nil {
		return
	}
	m.OpenAgeSeconds.Reset()
	for status, age := range ages {
		m.OpenAgeSeconds.WithLabelValues(status).Set(age)
	}
}
