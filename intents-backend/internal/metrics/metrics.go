// Package metrics holds the Prometheus collectors for the intents-backend.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics bundles every collector. One instance is created in main and passed
// by DI to the LI.FI client, the swap layer and the RPC clients.
type Metrics struct {
	LifiRequestTotal    *prometheus.CounterVec
	LifiRequestDuration *prometheus.HistogramVec
	LifiBackpressure    *prometheus.CounterVec
	LifiBreakerState    prometheus.Gauge

	SwapPrepareTotal  *prometheus.CounterVec
	SwapFinalizeTotal *prometheus.CounterVec
	BroadcastDuration *prometheus.HistogramVec
	RPCFailover       *prometheus.CounterVec
	BroadcastUnknown  *prometheus.CounterVec
	QuoteCacheTotal   *prometheus.CounterVec
}

// New registers every collector on the given registry. Using a dedicated
// registry (not the default) keeps the test surface clean and avoids global
// state leaking between processes.
func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		LifiRequestTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_lifi_request_total",
			Help: "LI.FI requests by endpoint and result.",
		}, []string{"endpoint", "result"}),
		LifiRequestDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "intents_lifi_request_duration_seconds",
			Help:    "LI.FI request latency by endpoint.",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint"}),
		LifiBackpressure: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_lifi_backpressure_total",
			Help: "Times the local LI.FI limiter rejected/delayed a call by endpoint.",
		}, []string{"endpoint"}),
		LifiBreakerState: f.NewGauge(prometheus.GaugeOpts{
			Name: "intents_lifi_breaker_state",
			Help: "LI.FI circuit breaker state (0=closed, 1=half-open, 2=open).",
		}),
		SwapPrepareTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_swap_prepare_total",
			Help: "Swap prepare calls by chain kind and result.",
		}, []string{"chain_kind", "result"}),
		SwapFinalizeTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_swap_finalize_total",
			Help: "Swap finalize (sign-insert + broadcast) calls by chain kind and result.",
		}, []string{"chain_kind", "result"}),
		BroadcastDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "intents_broadcast_duration_seconds",
			Help:    "Broadcast latency by chain kind.",
			Buckets: prometheus.DefBuckets,
		}, []string{"chain_kind"}),
		RPCFailover: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_rpc_failover_total",
			Help: "RPC failover attempts by chain kind and chain id.",
		}, []string{"chain_kind", "chain_id"}),
		BroadcastUnknown: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_broadcast_unknown_total",
			Help: "Broadcasts whose outcome is unknown after a possible send.",
		}, []string{"chain_kind", "chain_id"}),
		QuoteCacheTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "intents_quote_cache_total",
			Help: "Quote preview cache lookups by result (hit|miss).",
		}, []string{"result"}),
	}
}
