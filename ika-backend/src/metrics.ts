/**
 * Prometheus metrics for ika-backend.
 *
 * Singleton registry shared by HTTP middleware, pg pool scraper, gRPC
 * client, Solana RPC wrapper and gas sponsor. Exposed via `GET /metrics`
 * on the engine HTTP port; the engine sits on the private Railway network
 * so the endpoint is unauthenticated by design.
 *
 * The registry is namespaced under `ika_` so Grafana panels can filter
 * by service without dashboards colliding with `gateway_*` / `backend_*`.
 */

import { collectDefaultMetrics, Counter, Gauge, Histogram, Registry } from 'prom-client'
import { Router, type Request, type Response } from 'express'

import { getPool } from './store/pool.js'

const NAMESPACE = 'ika'

export const registry = new Registry()
collectDefaultMetrics({ register: registry, prefix: `${NAMESPACE}_` })

// ---------- HTTP ----------

export const httpRequestsTotal = new Counter({
  name: `${NAMESPACE}_http_requests_total`,
  help: 'HTTP requests by method, route, and status.',
  labelNames: ['method', 'route', 'status'],
  registers: [registry],
})

export const httpRequestDuration = new Histogram({
  name: `${NAMESPACE}_http_request_duration_seconds`,
  help: 'End-to-end engine latency.',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
  registers: [registry],
})

export const httpInFlight = new Gauge({
  name: `${NAMESPACE}_http_in_flight`,
  help: 'HTTP requests currently being processed.',
  registers: [registry],
})

// ---------- Postgres pool (node-postgres) ----------
// node-postgres surfaces only totalCount/idleCount/waitingCount.
// We sample them every 15s; the scraper is started by attachMetricsRoute.

export const dbPoolTotal = new Gauge({
  name: `${NAMESPACE}_db_pool_total`,
  help: 'pg.Pool.totalCount — all clients (idle + active + connecting).',
  registers: [registry],
})

export const dbPoolIdle = new Gauge({
  name: `${NAMESPACE}_db_pool_idle`,
  help: 'pg.Pool.idleCount — clients sitting idle in the pool.',
  registers: [registry],
})

export const dbPoolWaiting = new Gauge({
  name: `${NAMESPACE}_db_pool_waiting`,
  help: 'pg.Pool.waitingCount — callers queued waiting for a free client.',
  registers: [registry],
})

export const dbPoolErrors = new Counter({
  name: `${NAMESPACE}_db_pool_errors_total`,
  help: 'Cumulative pg.Pool errors (acquire failures, idle client errors).',
  labelNames: ['kind'],
  registers: [registry],
})

// ---------- gRPC (Ika DWalletService) ----------

export const grpcCallDuration = new Histogram({
  name: `${NAMESPACE}_grpc_call_duration_seconds`,
  help: 'gRPC unary call latency per method, with outcome label.',
  labelNames: ['method', 'outcome'],
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60],
  registers: [registry],
})

export const grpcCallTotal = new Counter({
  name: `${NAMESPACE}_grpc_calls_total`,
  help: 'gRPC call attempts by method and outcome (ok|unavailable|deadline|other).',
  labelNames: ['method', 'outcome'],
  registers: [registry],
})

export const grpcRetries = new Counter({
  name: `${NAMESPACE}_grpc_retries_total`,
  help: 'gRPC retry attempts by method.',
  labelNames: ['method'],
  registers: [registry],
})

export const grpcBreakerState = new Gauge({
  name: `${NAMESPACE}_grpc_breaker_state`,
  help: 'gRPC circuit-breaker state per method (0=closed, 1=open, 2=half-open).',
  labelNames: ['method'],
  registers: [registry],
})

export const grpcBreakerTripsTotal = new Counter({
  name: `${NAMESPACE}_grpc_breaker_trips_total`,
  help: 'Cumulative count of gRPC circuit-breaker open transitions per method.',
  labelNames: ['method'],
  registers: [registry],
})

// ---------- Solana RPC ----------

export const solanaRpcDuration = new Histogram({
  name: `${NAMESPACE}_solana_rpc_duration_seconds`,
  help: 'Solana RPC call latency by operation and outcome.',
  labelNames: ['op', 'outcome'],
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
  registers: [registry],
})

export const solanaRpcTotal = new Counter({
  name: `${NAMESPACE}_solana_rpc_total`,
  help: 'Solana RPC calls by op and outcome (ok|429|503|timeout|blockhash_expired|simulation_failed|other).',
  labelNames: ['op', 'outcome'],
  registers: [registry],
})

export const solanaRpcBreakerState = new Gauge({
  name: `${NAMESPACE}_solana_rpc_breaker_state`,
  help: 'Solana RPC circuit-breaker state per op (0=closed, 1=open, 2=half-open).',
  labelNames: ['op'],
  registers: [registry],
})

export const solanaRpcBreakerTripsTotal = new Counter({
  name: `${NAMESPACE}_solana_rpc_breaker_trips_total`,
  help: 'Cumulative count of Solana RPC circuit-breaker open transitions per op.',
  labelNames: ['op'],
  registers: [registry],
})

export const solanaBlockhashCacheHits = new Counter({
  name: `${NAMESPACE}_solana_blockhash_cache_hits_total`,
  help: 'Cumulative getCachedBlockhash() hits (no RPC round-trip).',
  registers: [registry],
})

export const solanaBlockhashCacheMisses = new Counter({
  name: `${NAMESPACE}_solana_blockhash_cache_misses_total`,
  help: 'Cumulative getCachedBlockhash() misses (had to fetch from RPC).',
  registers: [registry],
})

// ---------- Gas sponsor ----------

export const gasSponsorRequestsTotal = new Counter({
  name: `${NAMESPACE}_gas_sponsor_requests_total`,
  help: 'Gas sponsor send attempts by outcome.',
  labelNames: ['op_kind', 'outcome'],
  registers: [registry],
})

export const gasSponsorDuration = new Histogram({
  name: `${NAMESPACE}_gas_sponsor_duration_seconds`,
  help: 'End-to-end gas sponsor latency (build + simulate + send + confirm) by outcome.',
  labelNames: ['op_kind', 'outcome'],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
  registers: [registry],
})

export const gasSponsorLamportsSpent = new Counter({
  name: `${NAMESPACE}_gas_sponsor_lamports_spent_total`,
  help: 'Cumulative lamports spent by op_kind. Read via rate() for SOL/sec spend.',
  labelNames: ['op_kind'],
  registers: [registry],
})

export const gasSponsorBalanceLamports = new Gauge({
  name: `${NAMESPACE}_gas_sponsor_balance_lamports`,
  help: 'Last known gas sponsor balance (lamports). Updated after each successful send.',
  registers: [registry],
})

export const gasSponsorDuplicateSignature = new Counter({
  name: `${NAMESPACE}_gas_sponsor_duplicate_signature_total`,
  help: 'Cumulative Solana sendTransaction calls that returned duplicate-signature.',
  registers: [registry],
})

// P0.5: queue per fee payer. Depth measures concurrent in-flight + queued
// requests for one fee payer address; wait is the time a request spent
// waiting in the queue before its `fn` started running.
export const gasSponsorQueueDepth = new Gauge({
  name: `${NAMESPACE}_gas_sponsor_queue_depth`,
  help: 'Requests currently queued or in flight for a fee payer.',
  labelNames: ['fee_payer'],
  registers: [registry],
})

export const gasSponsorQueueWait = new Histogram({
  name: `${NAMESPACE}_gas_sponsor_queue_wait_seconds`,
  help: 'Seconds a request waited in the fee payer queue before signAndSendInstructions began.',
  labelNames: ['fee_payer'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
  registers: [registry],
})

export const gasSponsorRejectedTotal = new Counter({
  name: `${NAMESPACE}_gas_sponsor_rejected_total`,
  help: 'Gas sponsor requests rejected because the queue exceeded its cap (backpressure).',
  labelNames: ['fee_payer'],
  registers: [registry],
})

// ---------- Idempotency ----------

export const idempotencyHits = new Counter({
  name: `${NAMESPACE}_idempotency_hits_total`,
  help: 'Idempotency cache hits (returned a previously-cached response).',
  registers: [registry],
})

export const idempotencyMisses = new Counter({
  name: `${NAMESPACE}_idempotency_misses_total`,
  help: 'Idempotency cache misses (new key, mutation proceeded).',
  registers: [registry],
})

export const idempotencyConflicts = new Counter({
  name: `${NAMESPACE}_idempotency_conflicts_total`,
  help: 'Idempotency key reuse with mismatched body hash (HTTP 422).',
  registers: [registry],
})

// ---------- HTTP middleware ----------

/**
 * Express middleware that records HTTP latency, status and in-flight
 * count. Route label is best-effort: req.route.path when chi-style
 * matching is available, else req.path. We deliberately do not include
 * dWallet IDs or other high-cardinality identifiers.
 */
export function metricsMiddleware() {
  return (req: Request, res: Response, next: () => void) => {
    if (req.path === '/metrics') {
      next()
      return
    }
    const started = process.hrtime.bigint()
    httpInFlight.inc()
    res.on('finish', () => {
      httpInFlight.dec()
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9
      const fallback = (req.baseUrl ?? '') + (req.path === '/' ? '' : req.path)
      const route = (req.route?.path as string | undefined) ?? (fallback || 'unknown')
      httpRequestDuration.labels(req.method, route).observe(elapsed)
      httpRequestsTotal.labels(req.method, route, String(res.statusCode)).inc()
    })
    next()
  }
}

let scraperStarted = false
let scraperHandle: NodeJS.Timeout | null = null

/**
 * Mounts `GET /metrics` and starts the pg pool scraper. Safe to call
 * once at boot — subsequent calls are no-ops (idempotent).
 */
export function buildMetricsRouter(): Router {
  const router = Router()
  router.get('/metrics', async (_req, res) => {
    res.setHeader('Content-Type', registry.contentType)
    res.send(await registry.metrics())
  })
  if (!scraperStarted) {
    scraperStarted = true
    const scrape = () => {
      try {
        const pool = getPool()
        dbPoolTotal.set(pool.totalCount)
        dbPoolIdle.set(pool.idleCount)
        dbPoolWaiting.set(pool.waitingCount)
      } catch {
        // pool not initialised yet — silently skip; next tick will retry.
      }
    }
    scrape()
    scraperHandle = setInterval(scrape, 15_000)
    if (typeof scraperHandle.unref === 'function') scraperHandle.unref()
  }
  return router
}

/** Test hook: stop the pg pool scraper. */
export function stopMetricsScraper(): void {
  if (scraperHandle) {
    clearInterval(scraperHandle)
    scraperHandle = null
  }
  scraperStarted = false
}
