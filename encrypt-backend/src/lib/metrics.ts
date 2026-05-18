/**
 * Prometheus metrics for encrypt-backend.
 *
 * Registry is namespaced under `encrypt_` so dashboards can filter
 * by service. Surface mirrors ika-backend so a single Grafana panel
 * can compare engines side-by-side: HTTP, Solana RPC, blockhash cache,
 * idempotency, and gas sponsor (infrastructure ready though endpoints
 * still use the custody-free prepare/submit flow today).
 *
 * The endpoint mounts at `GET /metrics` on the Hono app — encrypt-backend
 * sits behind X-Internal-Key on a private Railway network, so /metrics is
 * unauthenticated by design.
 */

import { collectDefaultMetrics, Counter, Gauge, Histogram, Registry } from 'prom-client';
import type { Context, Next } from 'hono';

const NAMESPACE = 'encrypt';

export const registry = new Registry();
collectDefaultMetrics({ register: registry, prefix: `${NAMESPACE}_` });

// ---------- HTTP ----------

export const httpRequestsTotal = new Counter({
  name: `${NAMESPACE}_http_requests_total`,
  help: 'HTTP requests by method, route, and status.',
  labelNames: ['method', 'route', 'status'],
  registers: [registry],
});

export const httpRequestDuration = new Histogram({
  name: `${NAMESPACE}_http_request_duration_seconds`,
  help: 'End-to-end engine latency.',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
  registers: [registry],
});

export const httpInFlight = new Gauge({
  name: `${NAMESPACE}_http_in_flight`,
  help: 'HTTP requests currently being processed.',
  registers: [registry],
});

// ---------- Solana RPC ----------

export const solanaRpcDuration = new Histogram({
  name: `${NAMESPACE}_solana_rpc_duration_seconds`,
  help: 'Solana RPC call latency by op and outcome.',
  labelNames: ['op', 'outcome'],
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
  registers: [registry],
});

export const solanaRpcTotal = new Counter({
  name: `${NAMESPACE}_solana_rpc_total`,
  help: 'Solana RPC calls by op and outcome (ok|429|503|timeout|blockhash_expired|simulation_failed|circuit_open|other).',
  labelNames: ['op', 'outcome'],
  registers: [registry],
});

export const solanaRpcBreakerState = new Gauge({
  name: `${NAMESPACE}_solana_rpc_breaker_state`,
  help: 'Solana RPC circuit-breaker state per op (0=closed, 1=open, 2=half-open).',
  labelNames: ['op'],
  registers: [registry],
});

export const solanaRpcBreakerTripsTotal = new Counter({
  name: `${NAMESPACE}_solana_rpc_breaker_trips_total`,
  help: 'Cumulative count of Solana RPC circuit-breaker open transitions per op.',
  labelNames: ['op'],
  registers: [registry],
});

// ---------- Blockhash cache ----------

export const blockhashCacheHits = new Counter({
  name: `${NAMESPACE}_solana_blockhash_cache_hits_total`,
  help: 'Cumulative blockhash cache hits (no RPC round-trip).',
  registers: [registry],
});

export const blockhashCacheMisses = new Counter({
  name: `${NAMESPACE}_solana_blockhash_cache_misses_total`,
  help: 'Cumulative blockhash cache misses (had to fetch from RPC).',
  registers: [registry],
});

export const blockhashCacheInvalidations = new Counter({
  name: `${NAMESPACE}_solana_blockhash_cache_invalidations_total`,
  help: 'Cumulative blockhash cache invalidations (BlockhashNotFound / TransactionExpired).',
  registers: [registry],
});

// ---------- Idempotency ----------

export const idempotencyHits = new Counter({
  name: `${NAMESPACE}_idempotency_hits_total`,
  help: 'Idempotency cache hits (returned a previously-cached response).',
  registers: [registry],
});

export const idempotencyMisses = new Counter({
  name: `${NAMESPACE}_idempotency_misses_total`,
  help: 'Idempotency cache misses (new key, mutation proceeded).',
  registers: [registry],
});

export const idempotencyConflicts = new Counter({
  name: `${NAMESPACE}_idempotency_conflicts_total`,
  help: 'Idempotency key reuse with mismatched body hash (HTTP 422).',
  registers: [registry],
});

// ---------- Gas sponsor ----------

export const gasSponsorDuration = new Histogram({
  name: `${NAMESPACE}_gas_sponsor_duration_seconds`,
  help: 'End-to-end gas sponsor latency by outcome.',
  labelNames: ['op_kind', 'outcome'],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
  registers: [registry],
});

export const gasSponsorQueueDepth = new Gauge({
  name: `${NAMESPACE}_gas_sponsor_queue_depth`,
  help: 'Requests currently queued or in flight for a fee payer.',
  labelNames: ['fee_payer'],
  registers: [registry],
});

export const gasSponsorQueueWait = new Histogram({
  name: `${NAMESPACE}_gas_sponsor_queue_wait_seconds`,
  help: 'Seconds a request waited in the fee payer queue before sign-and-send began.',
  labelNames: ['fee_payer'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
  registers: [registry],
});

export const gasSponsorRejectedTotal = new Counter({
  name: `${NAMESPACE}_gas_sponsor_rejected_total`,
  help: 'Gas sponsor requests rejected because the queue exceeded its cap (backpressure).',
  labelNames: ['fee_payer'],
  registers: [registry],
});

export const gasSponsorRequestsTotal = new Counter({
  name: `${NAMESPACE}_gas_sponsor_requests_total`,
  help: 'Gas sponsor send attempts by outcome.',
  labelNames: ['op_kind', 'outcome'],
  registers: [registry],
});

// ---------- Hono middleware ----------

/**
 * Hono middleware: records HTTP latency, status and in-flight count.
 * Route label is best-effort: routePath() when available, falling back
 * to req.path. We deliberately avoid request-body identifiers to keep
 * cardinality bounded.
 */
export function metricsMiddleware() {
  return async (c: Context, next: Next): Promise<void> => {
    if (c.req.path === '/metrics') {
      await next();
      return;
    }
    const started = process.hrtime.bigint();
    httpInFlight.inc();
    try {
      await next();
    } finally {
      httpInFlight.dec();
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
      const route = (typeof c.req.routePath === 'string' ? c.req.routePath : c.req.path) || 'unknown';
      httpRequestDuration.labels(c.req.method, route).observe(elapsed);
      httpRequestsTotal.labels(c.req.method, route, String(c.res.status)).inc();
    }
  };
}

/**
 * Maps a Solana RPC error to a bounded Prometheus label.
 * Keeps cardinality to {ok, 429, 503, timeout, blockhash_expired,
 * simulation_failed, other}.
 */
export function classifySolanaRpcError(err: unknown): string {
  if (!err) return 'ok';
  const msg = String((err as { message?: string }).message ?? err).toLowerCase();
  const code = (err as { code?: number }).code;
  if (code === 429 || msg.includes('429') || msg.includes('rate limit')) return '429';
  if (code === 503 || msg.includes('503') || msg.includes('service unavailable')) return '503';
  if (msg.includes('timeout') || msg.includes('deadline')) return 'timeout';
  if (msg.includes('blockhash not found') || msg.includes('blockheight exceeded')) return 'blockhash_expired';
  if (msg.includes('simulation') || msg.includes('preflight')) return 'simulation_failed';
  return 'other';
}
