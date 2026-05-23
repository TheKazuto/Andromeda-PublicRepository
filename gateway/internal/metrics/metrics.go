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
	"time"

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
	QuotaConsumedTotal    *prometheus.CounterVec // labels: plan, bucket (credits|monthly|overage)
	QuotaExceededTotal    *prometheus.CounterVec // labels: plan
	RateLimitBlockedTotal *prometheus.CounterVec // labels: class (read|tx)

	// Upstream — emitted by the proxy handler.
	UpstreamRequestsTotal    *prometheus.CounterVec   // labels: upstream, status_class
	UpstreamLatency          *prometheus.HistogramVec // labels: upstream
	CircuitBreakerState      *prometheus.GaugeVec     // labels: upstream  (0=closed,1=open,2=half-open)
	CircuitBreakerTripsTotal *prometheus.CounterVec   // labels: upstream

	// Usage recorder backpressure — gauges scraped from the recorder.
	UsageBufferDepth prometheus.Gauge
	UsageBufferDrops prometheus.Counter

	// Worker ticks — diagnostics for slow workers.
	WorkerTickTotal *prometheus.CounterVec // labels: worker, outcome

	// Webhooks: DLQ depth (gauge sampled periodically) and on-chain
	// listener drops (counter incremented inline by the rate limiter).
	WebhookDLQDepth       prometheus.Gauge
	ListenerEventsDropped *prometheus.CounterVec // labels: reason

	// WebhookPublishFailures counts every Publish() call that returned an
	// error before any delivery was enqueued (DB outage, marshal failure,
	// etc.). Distinct from ListenerEventsDropped, which counts ingress
	// drops before Publish is even invoked.
	WebhookPublishFailures *prometheus.CounterVec // labels: event_type

	// WebhookDeliveriesTotal counts dispatcher outcomes per attempt: 2xx,
	// 4xx, 5xx, network_error, dead_letter. Used together with
	// `gateway_webhook_dlq_depth` to alert on persistent failures.
	WebhookDeliveriesTotal *prometheus.CounterVec // labels: outcome

	// WebhookRateLimitedTotal counts deliveries deferred because the
	// per-destination token bucket was empty at the dispatcher worker.
	// No labels — endpoint_id cardinality would blow up the series
	// count.
	WebhookRateLimitedTotal prometheus.Counter

	// Webhook backlog — sampled every 15s by the metrics scraper.
	WebhookInFlightCount         prometheus.Gauge
	WebhookPendingCount          prometheus.Gauge
	WebhookOldestPendingSeconds  prometheus.Gauge
	WebhookOldestInFlightSeconds prometheus.Gauge

	// Postgres pgxpool — sampled every 15s by the metrics scraper.
	// Mirrors pgxpool.Stat() so dashboards can alert on acquire wait /
	// pool saturation per the robustness plan F0/F1 tasks.
	DBPoolAcquired             prometheus.Gauge
	DBPoolIdle                 prometheus.Gauge
	DBPoolTotal                prometheus.Gauge
	DBPoolMax                  prometheus.Gauge
	DBPoolNewConnsTotal        prometheus.Gauge // monotonic counter sourced from pgxpool; expose as gauge of "current value"
	DBPoolAcquireCount         prometheus.Gauge
	DBPoolEmptyAcquireTotal    prometheus.Gauge
	DBPoolCanceledAcquireTotal prometheus.Gauge
	DBPoolAcquireWaitSeconds   prometheus.Gauge // total wait time so far, in seconds (cumulative)

	// Redis — per-operation latency histogram + error counter. Op label
	// is the high-level operation name (`ratelimit_eval`, `idempotency_get`,
	// `idempotency_set`, `set_nx`). Keep cardinality bounded.
	RedisOpLatency *prometheus.HistogramVec // labels: op
	RedisErrors    *prometheus.CounterVec   // labels: op, kind (timeout|conn|other)
	RedisFailOpen  *prometheus.CounterVec   // labels: op (rate limit fails open when Redis unreachable)

	// Audit signer — latency per signature + failure counter. Backend
	// label distinguishes `env` (in-memory ed25519) from `vault` (Vault
	// Transit HTTP round-trip).
	AuditSignerLatency       *prometheus.HistogramVec // labels: backend
	AuditAppendLatency       prometheus.Histogram     // end-to-end Recorder.Append wall time
	AuditFailuresTotal       *prometheus.CounterVec   // labels: stage (sign|append|update|commit)
	AuditDegraded            prometheus.Gauge         // 0 = healthy, 1 = signer unavailable / fallback active
	AuditOutboxDepth         prometheus.Gauge         // rows with signature IS NULL waiting to be signed
	AuditOutboxOldestSeconds prometheus.Gauge         // age in seconds of the oldest pending signature

	// Audit snapshot worker — daily R2/S3 dump for DR.
	AuditSnapshotRowsTotal       prometheus.Counter
	AuditSnapshotBytesTotal      prometheus.Counter
	AuditSnapshotFailuresTotal   *prometheus.CounterVec // labels: stage (cursor|fetch|build|upload|record)
	AuditSnapshotLastSuccessUnix prometheus.Gauge       // unix timestamp of the last successful tick

	// Gas sponsor — latency for sign-and-send (single fee payer for now;
	// P0.5 introduces a pool with per-key labels). Result label is
	// `submitted` / `simulation_failed` / `rpc_error` / `rejected`.
	GasSponsorLatency      *prometheus.HistogramVec // labels: result
	GasSponsorRequests     *prometheus.CounterVec   // labels: result
	GasSponsorDuplicateSig prometheus.Counter

	// Oracle price-trigger monitor (F7.5) + oracle feed relay. Bounded labels
	// only (no per-feed/per-tenant) to keep series count flat.
	OracleTriggerFiresTotal   *prometheus.CounterVec // labels: result (fired|failed)
	OracleTriggerExpiredTotal prometheus.Counter
	OracleMonitorErrorsTotal  *prometheus.CounterVec // labels: stage (tick|hermes|claim|reap)
	OracleFeedRefreshTotal    *prometheus.CounterVec // labels: result (success|skipped|stale|error)
	OracleArmedTriggers       prometheus.Gauge       // armed price triggers (sampled every 15s)

	// Async presign prefetch (Update 2 Part A). Bounded labels only.
	PresignPrefetchTotal *prometheus.CounterVec // labels: result (ok|error) — background presign dispatched at challenge time
	PresignHarvestTotal  *prometheus.CounterVec // labels: result (hit|miss) — submit lookup of the prefetched presign

	// Risk blocklist ingestor (H4). Bounded labels only (no per-feed cardinality explosion).
	RiskFeedDownloadFailuresTotal   *prometheus.CounterVec // labels: source
	RiskFeedVariationSkipsTotal     *prometheus.CounterVec // labels: source
	RiskFeedEntriesUpsertedTotal    *prometheus.CounterVec // labels: source
	RiskFeedLastSuccessSecondsGauge *prometheus.GaugeVec   // labels: source (unix ts of last success per feed)
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
	m.WebhookPublishFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "webhook",
			Name:      "publish_failures_total",
			Help:      "Publish() invocations that failed before any delivery was enqueued, by event_type.",
		}, []string{"event_type"})
	m.WebhookDeliveriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "webhook",
			Name:      "deliveries_total",
			Help:      "Delivery attempts by outcome (2xx/4xx/5xx/network_error/dead_letter).",
		}, []string{"outcome"})
	m.WebhookRateLimitedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "rate_limited_total",
		Help:      "Cumulative deliveries deferred because the per-endpoint token bucket was empty.",
	})

	m.ListenerEventsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "listener",
			Name:      "events_dropped_total",
			Help:      "On-chain events dropped before publish (rate_limit / no_tenant / parse_error).",
		}, []string{"reason"})

	// --- Webhook backlog gauges (sampled by metrics scraper) ---
	m.WebhookInFlightCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "in_flight_count",
		Help:      "Webhook deliveries currently marked in_flight (claimed by a dispatcher).",
	})
	m.WebhookPendingCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "pending_count",
		Help:      "Webhook deliveries currently pending (waiting for next_attempt_at).",
	})
	m.WebhookOldestPendingSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "oldest_pending_age_seconds",
		Help:      "Age in seconds of the oldest pending (eligible) webhook delivery; 0 when queue is empty.",
	})
	m.WebhookOldestInFlightSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "webhook",
		Name:      "oldest_in_flight_age_seconds",
		Help:      "Age in seconds of the oldest in_flight webhook delivery; alerts on stuck/crashed dispatchers.",
	})

	// --- DB pool gauges (pgxpool.Stat sampled by metrics scraper) ---
	m.DBPoolAcquired = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "acquired_conns",
		Help: "Postgres connections currently checked out (pgxpool.Stat.AcquiredConns).",
	})
	m.DBPoolIdle = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "idle_conns",
		Help: "Postgres connections currently idle in the pool (pgxpool.Stat.IdleConns).",
	})
	m.DBPoolTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "total_conns",
		Help: "Total open Postgres connections (pgxpool.Stat.TotalConns).",
	})
	m.DBPoolMax = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "max_conns",
		Help: "Configured pool ceiling (pgxpool.Config.MaxConns).",
	})
	m.DBPoolNewConnsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "new_conns_total",
		Help: "Cumulative new connections opened (pgxpool.Stat.NewConnsCount).",
	})
	m.DBPoolAcquireCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "acquire_count_total",
		Help: "Cumulative successful Acquire() calls (pgxpool.Stat.AcquireCount).",
	})
	m.DBPoolEmptyAcquireTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "empty_acquire_total",
		Help: "Cumulative Acquire() calls that had to wait on an empty pool (pgxpool.Stat.EmptyAcquireCount).",
	})
	m.DBPoolCanceledAcquireTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "canceled_acquire_total",
		Help: "Cumulative Acquire() calls cancelled before getting a connection (pgxpool.Stat.CanceledAcquireCount).",
	})
	m.DBPoolAcquireWaitSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "db_pool", Name: "acquire_wait_seconds_total",
		Help: "Cumulative wall time spent waiting in Acquire() (pgxpool.Stat.AcquireDuration, seconds).",
	})

	// --- Redis ---
	m.RedisOpLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gateway", Subsystem: "redis", Name: "op_latency_seconds",
		Help:    "Latency of Redis operations by logical op name (ratelimit_eval, idempotency_get, …).",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	}, []string{"op"})
	m.RedisErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "redis", Name: "errors_total",
		Help: "Redis errors by op and coarse kind (timeout|conn|other).",
	}, []string{"op", "kind"})
	m.RedisFailOpen = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "redis", Name: "fail_open_total",
		Help: "Times a feature fell open because Redis was unavailable (rate limit).",
	}, []string{"op"})

	// --- Audit signer ---
	m.AuditSignerLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "signer_latency_seconds",
		Help:    "Wall time of one ed25519 signature (env: in-memory; vault: Vault Transit HTTP round-trip).",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	}, []string{"backend"})
	m.AuditAppendLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "append_latency_seconds",
		Help:    "End-to-end Recorder.Append wall time (lock + tx + prev lookup + sign + insert + commit).",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	})
	m.AuditFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "failures_total",
		Help: "Audit failures by stage (sign|append).",
	}, []string{"stage"})
	m.AuditDegraded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "degraded",
		Help: "1 when the audit signer is unavailable or running in fallback mode, 0 otherwise.",
	})
	m.AuditOutboxDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "outbox_depth",
		Help: "Rows in audit_log with signature IS NULL waiting to be signed by the worker.",
	})
	m.AuditOutboxOldestSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "outbox_oldest_age_seconds",
		Help: "Age in seconds of the oldest row waiting for signature; 0 when the outbox is empty.",
	})
	m.AuditSnapshotRowsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "snapshot_rows_total",
		Help: "Cumulative audit_log rows uploaded to R2/S3 by the snapshotter worker.",
	})
	m.AuditSnapshotBytesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "snapshot_bytes_total",
		Help: "Cumulative compressed bytes uploaded to R2/S3 by the snapshotter worker.",
	})
	m.AuditSnapshotFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "snapshot_failures_total",
		Help: "Audit snapshot worker failures by stage (cursor|fetch|build|upload|record).",
	}, []string{"stage"})
	m.AuditSnapshotLastSuccessUnix = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "audit", Name: "snapshot_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful snapshot tick; 0 until first success.",
	})

	// --- Gas sponsor ---
	m.GasSponsorLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gateway", Subsystem: "gas_sponsor", Name: "latency_seconds",
		Help:    "End-to-end gas sponsor send latency by outcome.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
	}, []string{"result"})
	m.GasSponsorRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "gas_sponsor", Name: "requests_total",
		Help: "Gas sponsor send attempts by outcome (submitted|simulation_failed|rpc_error|rejected).",
	}, []string{"result"})
	m.OracleTriggerFiresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "oracle_monitor",
			Name:      "trigger_fires_total",
			Help:      "Price-trigger fire attempts by result (fired = request_signature landed; failed = fire errored).",
		}, []string{"result"})
	m.OracleTriggerExpiredTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway",
		Subsystem: "oracle_monitor",
		Name:      "triggers_expired_total",
		Help:      "Armed price triggers reaped at expiry without ever firing.",
	})
	m.OracleMonitorErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "oracle_monitor",
			Name:      "errors_total",
			Help:      "Monitor loop errors by stage (tick|hermes|claim|reap).",
		}, []string{"stage"})
	m.OracleFeedRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gateway",
			Subsystem: "oracle_relay",
			Name:      "feed_refresh_total",
			Help:      "FeedCache refresh outcomes by result (success|skipped|stale|error).",
		}, []string{"result"})
	m.OracleArmedTriggers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gateway",
		Subsystem: "oracle_monitor",
		Name:      "armed_triggers",
		Help:      "Price triggers currently armed (sampled every 15s by the metrics scraper).",
	})

	m.PresignPrefetchTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "presign_prefetch", Name: "dispatched_total",
		Help: "Background presigns dispatched at signing-challenge time, by result (ok|error).",
	}, []string{"result"})
	m.PresignHarvestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "presign_prefetch", Name: "harvest_total",
		Help: "Submit lookups of the prefetched presign, by result (hit|miss). hit/(hit+miss) = cache-hit rate.",
	}, []string{"result"})

	m.GasSponsorDuplicateSig = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "gas_sponsor", Name: "duplicate_signature_total",
		Help: "Cumulative count of Solana sendTransaction calls that returned duplicate-signature.",
	})

	m.RiskFeedDownloadFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "risk", Name: "feed_download_failures_total",
		Help: "Risk blocklist feed download failures by source.",
	}, []string{"source"})
	m.RiskFeedVariationSkipsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "risk", Name: "feed_variation_skips_total",
		Help: "Risk blocklist feed updates skipped due to variation threshold by source.",
	}, []string{"source"})
	m.RiskFeedEntriesUpsertedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gateway", Subsystem: "risk", Name: "feed_entries_upserted_total",
		Help: "Risk blocklist entries successfully upserted by source.",
	}, []string{"source"})
	m.RiskFeedLastSuccessSecondsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "gateway", Subsystem: "risk", Name: "feed_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful ingestion per feed source.",
	}, []string{"source"})

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
		m.WebhookPublishFailures,
		m.WebhookDeliveriesTotal,
		m.WebhookRateLimitedTotal,
		m.WebhookInFlightCount,
		m.WebhookPendingCount,
		m.WebhookOldestPendingSeconds,
		m.WebhookOldestInFlightSeconds,
		m.DBPoolAcquired,
		m.DBPoolIdle,
		m.DBPoolTotal,
		m.DBPoolMax,
		m.DBPoolNewConnsTotal,
		m.DBPoolAcquireCount,
		m.DBPoolEmptyAcquireTotal,
		m.DBPoolCanceledAcquireTotal,
		m.DBPoolAcquireWaitSeconds,
		m.RedisOpLatency,
		m.RedisErrors,
		m.RedisFailOpen,
		m.PresignPrefetchTotal,
		m.PresignHarvestTotal,
		m.AuditSignerLatency,
		m.AuditAppendLatency,
		m.AuditFailuresTotal,
		m.AuditDegraded,
		m.AuditOutboxDepth,
		m.AuditOutboxOldestSeconds,
		m.AuditSnapshotRowsTotal,
		m.AuditSnapshotBytesTotal,
		m.AuditSnapshotFailuresTotal,
		m.AuditSnapshotLastSuccessUnix,
		m.GasSponsorLatency,
		m.GasSponsorRequests,
		m.GasSponsorDuplicateSig,
		m.OracleTriggerFiresTotal,
		m.OracleTriggerExpiredTotal,
		m.OracleMonitorErrorsTotal,
		m.OracleFeedRefreshTotal,
		m.OracleArmedTriggers,
		m.RiskFeedDownloadFailuresTotal,
		m.RiskFeedVariationSkipsTotal,
		m.RiskFeedEntriesUpsertedTotal,
		m.RiskFeedLastSuccessSecondsGauge,
	)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	return m, handler
}

// Registry exposes the underlying Prometheus registry for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// RecordPublishFailure implements webhooks.PublisherMetrics. Keeps the
// webhooks package free of a direct prometheus dependency.
func (m *Metrics) RecordPublishFailure(eventType string) {
	if m == nil || m.WebhookPublishFailures == nil {
		return
	}
	m.WebhookPublishFailures.WithLabelValues(eventType).Inc()
}

// RecordDeliveryOutcome implements webhooks.DispatcherMetrics.
func (m *Metrics) RecordDeliveryOutcome(outcome string) {
	if m == nil || m.WebhookDeliveriesTotal == nil {
		return
	}
	m.WebhookDeliveriesTotal.WithLabelValues(outcome).Inc()
}

// RecordWebhookRateLimited implements webhooks.DispatcherMetrics.
func (m *Metrics) RecordWebhookRateLimited() {
	if m == nil || m.WebhookRateLimitedTotal == nil {
		return
	}
	m.WebhookRateLimitedTotal.Inc()
}

// --- ratelimit.Observer adapter ---

// ObserveOpLatency records latency for a Redis-backed op (ratelimit_eval,
// idempotency_get, …). Implements ratelimit.Observer.
func (m *Metrics) ObserveOpLatency(op string, seconds float64) {
	if m == nil || m.RedisOpLatency == nil {
		return
	}
	m.RedisOpLatency.WithLabelValues(op).Observe(seconds)
}

// IncError increments redis_errors_total for the given op/kind.
// Implements ratelimit.Observer.
func (m *Metrics) IncError(op, kind string) {
	if m == nil || m.RedisErrors == nil {
		return
	}
	if kind == "" {
		kind = "other"
	}
	m.RedisErrors.WithLabelValues(op, kind).Inc()
}

// IncFailOpen increments redis_fail_open_total for the given op.
// Implements ratelimit.Observer.
func (m *Metrics) IncFailOpen(op string) {
	if m == nil || m.RedisFailOpen == nil {
		return
	}
	m.RedisFailOpen.WithLabelValues(op).Inc()
}

// --- policy.PresignMetrics adapter (Update 2 Part A) ---

// RecordPresignPrefetch counts a background presign dispatch (ok|error).
func (m *Metrics) RecordPresignPrefetch(ok bool) {
	if m == nil || m.PresignPrefetchTotal == nil {
		return
	}
	res := "ok"
	if !ok {
		res = "error"
	}
	m.PresignPrefetchTotal.WithLabelValues(res).Inc()
}

// RecordPresignHarvest counts a submit lookup of the prefetched presign (hit|miss).
func (m *Metrics) RecordPresignHarvest(hit bool) {
	if m == nil || m.PresignHarvestTotal == nil {
		return
	}
	res := "miss"
	if hit {
		res = "hit"
	}
	m.PresignHarvestTotal.WithLabelValues(res).Inc()
}

// --- audit.SignerObserver adapter ---

// ObserveAuditSign records one signature latency for the named signer
// backend (`env` | `vault`). Implements audit.SignerObserver.
func (m *Metrics) ObserveAuditSign(backend string, seconds float64) {
	if m == nil || m.AuditSignerLatency == nil {
		return
	}
	m.AuditSignerLatency.WithLabelValues(backend).Observe(seconds)
}

// ObserveAuditAppend records one Recorder.Append wall time.
func (m *Metrics) ObserveAuditAppend(seconds float64) {
	if m == nil || m.AuditAppendLatency == nil {
		return
	}
	m.AuditAppendLatency.Observe(seconds)
}

// IncAuditFailure increments audit_failures_total{stage=...}.
func (m *Metrics) IncAuditFailure(stage string) {
	if m == nil || m.AuditFailuresTotal == nil {
		return
	}
	m.AuditFailuresTotal.WithLabelValues(stage).Inc()
}

// SetAuditDegraded sets the audit_degraded gauge (1 = degraded).
func (m *Metrics) SetAuditDegraded(degraded bool) {
	if m == nil || m.AuditDegraded == nil {
		return
	}
	if degraded {
		m.AuditDegraded.Set(1)
	} else {
		m.AuditDegraded.Set(0)
	}
}

// SetAuditOutboxDepth records the current count of unsigned audit rows.
func (m *Metrics) SetAuditOutboxDepth(depth int64) {
	if m == nil || m.AuditOutboxDepth == nil {
		return
	}
	m.AuditOutboxDepth.Set(float64(depth))
}

// SetAuditOutboxOldestSeconds records the age of the oldest pending row.
func (m *Metrics) SetAuditOutboxOldestSeconds(seconds float64) {
	if m == nil || m.AuditOutboxOldestSeconds == nil {
		return
	}
	m.AuditOutboxOldestSeconds.Set(seconds)
}

// ObserveSnapshotUpload implements audit.SnapshotObserver. Records one
// successful upload's row + byte counts.
func (m *Metrics) ObserveSnapshotUpload(rows int, bytes int64) {
	if m == nil {
		return
	}
	if m.AuditSnapshotRowsTotal != nil {
		m.AuditSnapshotRowsTotal.Add(float64(rows))
	}
	if m.AuditSnapshotBytesTotal != nil {
		m.AuditSnapshotBytesTotal.Add(float64(bytes))
	}
}

// IncSnapshotFailure implements audit.SnapshotObserver.
func (m *Metrics) IncSnapshotFailure(stage string) {
	if m == nil || m.AuditSnapshotFailuresTotal == nil {
		return
	}
	m.AuditSnapshotFailuresTotal.WithLabelValues(stage).Inc()
}

// SetSnapshotLastSuccessUnix implements audit.SnapshotObserver.
func (m *Metrics) SetSnapshotLastSuccessUnix(unix int64) {
	if m == nil || m.AuditSnapshotLastSuccessUnix == nil {
		return
	}
	m.AuditSnapshotLastSuccessUnix.Set(float64(unix))
}

// RecordOracleTriggerFire implements oraclemonitor.Metrics — result is
// "fired" or "failed".
func (m *Metrics) RecordOracleTriggerFire(result string) {
	if m == nil || m.OracleTriggerFiresTotal == nil {
		return
	}
	m.OracleTriggerFiresTotal.WithLabelValues(result).Inc()
}

// RecordOracleTriggerExpired implements oraclemonitor.Metrics.
func (m *Metrics) RecordOracleTriggerExpired(n int) {
	if m == nil || m.OracleTriggerExpiredTotal == nil || n <= 0 {
		return
	}
	m.OracleTriggerExpiredTotal.Add(float64(n))
}

// RecordOracleMonitorError implements oraclemonitor.Metrics — stage is one of
// tick|hermes|claim|reap.
func (m *Metrics) RecordOracleMonitorError(stage string) {
	if m == nil || m.OracleMonitorErrorsTotal == nil {
		return
	}
	m.OracleMonitorErrorsTotal.WithLabelValues(stage).Inc()
}

// RecordOracleFeedRefresh implements oraclerelay.Metrics — result is one of
// success|skipped|stale|error.
func (m *Metrics) RecordOracleFeedRefresh(result string) {
	if m == nil || m.OracleFeedRefreshTotal == nil {
		return
	}
	m.OracleFeedRefreshTotal.WithLabelValues(result).Inc()
}

// SetOracleArmedTriggers updates the armed-price-triggers gauge. Sampled by the
// metrics scraper.
func (m *Metrics) SetOracleArmedTriggers(n int) {
	if m == nil || m.OracleArmedTriggers == nil {
		return
	}
	m.OracleArmedTriggers.Set(float64(n))
}

// --- risk.IngestorMetrics adapter (H4) ---

// RecordRiskFeedDownloadFailure implements risk.IngestorMetrics.
func (m *Metrics) RecordRiskFeedDownloadFailure(source string) {
	if m == nil || m.RiskFeedDownloadFailuresTotal == nil {
		return
	}
	m.RiskFeedDownloadFailuresTotal.WithLabelValues(source).Inc()
}

// RecordRiskFeedVariationSkip implements risk.IngestorMetrics.
func (m *Metrics) RecordRiskFeedVariationSkip(source string) {
	if m == nil || m.RiskFeedVariationSkipsTotal == nil {
		return
	}
	m.RiskFeedVariationSkipsTotal.WithLabelValues(source).Inc()
}

// RecordRiskFeedEntriesUpserted implements risk.IngestorMetrics.
func (m *Metrics) RecordRiskFeedEntriesUpserted(source string) {
	if m == nil || m.RiskFeedEntriesUpsertedTotal == nil {
		return
	}
	m.RiskFeedEntriesUpsertedTotal.WithLabelValues(source).Inc()
}

// RecordRiskFeedLastSuccessSeconds implements risk.IngestorMetrics — sets the unix ts.
func (m *Metrics) RecordRiskFeedLastSuccessSeconds(source string) {
	if m == nil || m.RiskFeedLastSuccessSecondsGauge == nil {
		return
	}
	m.RiskFeedLastSuccessSecondsGauge.WithLabelValues(source).Set(float64(time.Now().Unix()))
}

// StatusClass converts an HTTP status into a coarse class label
// (2xx/3xx/4xx/5xx). 0 → "error" (network failure, no response).
func StatusClass(status int) string {
	switch {
	case status == 0:
		return "error"
	case status == 499:
		// Client closed the connection mid-flight — not the upstream's fault.
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
