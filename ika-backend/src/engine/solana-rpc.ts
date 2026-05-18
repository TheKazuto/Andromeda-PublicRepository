import { createSolanaRpc, createSolanaRpcSubscriptions } from '@solana/kit'
import type { Rpc, SolanaRpcApi, RpcSubscriptions, SolanaRpcSubscriptionsApi } from '@solana/kit'

import { logger } from '../logger.js'
import {
  solanaBlockhashCacheHits,
  solanaBlockhashCacheMisses,
  solanaRpcBreakerState,
  solanaRpcBreakerTripsTotal,
  solanaRpcDuration,
  solanaRpcTotal,
} from '../metrics.js'
import {
  CircuitOpenError,
  getBreakerState,
  preCallGeneric,
  recordFailure,
  recordSuccess,
} from './breaker.js'

export { CircuitOpenError } from './breaker.js'

let rpc: Rpc<SolanaRpcApi> | null = null
let rpcSub: RpcSubscriptions<SolanaRpcSubscriptionsApi> | null = null

export function initSolanaRpc(url: string): Rpc<SolanaRpcApi> {
  rpc = createSolanaRpc(url)
  return rpc
}

export function getSolanaRpc(): Rpc<SolanaRpcApi> {
  if (!rpc) throw new Error('Solana RPC not initialized')
  return rpc
}

export function initSolanaRpcSubscriptions(url: string): RpcSubscriptions<SolanaRpcSubscriptionsApi> {
  const wsUrl = url.replace(/^http/, 'ws')
  rpcSub = createSolanaRpcSubscriptions(wsUrl)
  return rpcSub
}

export function getSolanaRpcSubscriptions(): RpcSubscriptions<SolanaRpcSubscriptionsApi> {
  if (!rpcSub) throw new Error('Solana RPC subscriptions not initialized')
  return rpcSub
}

// ── Blockhash cache (TTL + single-flight) ────────────────────────────────
//
// `getLatestBlockhash` é chamado em toda construção de transação não-assinada.
// Blockhashes Solana são válidos por ~150 slots (~60s). Cachear por uma
// fração desse tempo elimina dezenas de RPC calls por minuto sob carga.
//
// Single-flight: se 50 requests chegarem simultaneamente com cache miss,
// apenas 1 dispara a chamada RPC; os outros aguardam a mesma Promise.

interface BlockhashEntry {
  blockhash: string
  lastValidBlockHeight: bigint
  fetchedAt: number
}

const BLOCKHASH_TTL_MS = 10_000
let cachedBlockhash: BlockhashEntry | null = null
let inFlight: Promise<BlockhashEntry> | null = null

export interface CachedBlockhash {
  blockhash: string
  lastValidBlockHeight: bigint
}

export async function getCachedBlockhash(): Promise<CachedBlockhash> {
  const now = Date.now()
  if (cachedBlockhash && now - cachedBlockhash.fetchedAt < BLOCKHASH_TTL_MS) {
    solanaBlockhashCacheHits.inc()
    return {
      blockhash: cachedBlockhash.blockhash,
      lastValidBlockHeight: cachedBlockhash.lastValidBlockHeight,
    }
  }
  if (inFlight) {
    solanaBlockhashCacheHits.inc()
    const entry = await inFlight
    return { blockhash: entry.blockhash, lastValidBlockHeight: entry.lastValidBlockHeight }
  }
  solanaBlockhashCacheMisses.inc()
  // withSolanaRpc covers latency + outcome counter + breaker state for
  // getLatestBlockhash. The IIFE only owns the singleflight reset.
  inFlight = (async () => {
    try {
      const entry: BlockhashEntry = await withSolanaRpc('getLatestBlockhash', async () => {
        const { value: latest } = await getSolanaRpc()
          .getLatestBlockhash({ commitment: 'confirmed' })
          .send()
        return {
          blockhash: latest.blockhash,
          lastValidBlockHeight: latest.lastValidBlockHeight,
          fetchedAt: Date.now(),
        }
      })
      cachedBlockhash = entry
      return entry
    } finally {
      inFlight = null
    }
  })()
  const entry = await inFlight
  return { blockhash: entry.blockhash, lastValidBlockHeight: entry.lastValidBlockHeight }
}

/**
 * Invalidates the cached blockhash. Callers MUST invoke this whenever
 * Solana returns `BlockhashNotFound` / `TransactionExpiredBlockheightExceeded`
 * so subsequent transactions refetch a fresh one instead of looping on a
 * stale value.
 */
export function invalidateBlockhashCache(): void {
  cachedBlockhash = null
}

/**
 * withSolanaRpc wraps a Solana RPC call with a circuit breaker keyed by
 * op name (`getLatestBlockhash`, `sendTransaction`, …). Behavior:
 *   - When the breaker is open, throws CircuitOpenError immediately
 *     without touching the RPC. The caller should map this to 503 with
 *     Retry-After when surfacing to clients.
 *   - On success, the breaker is reset.
 *   - On failure, only "real" RPC faults (429/503/timeout/other) feed
 *     the breaker. `blockhash_expired` is normal under load and must
 *     not trip the breaker.
 *
 * Latency and outcome counters are also recorded so this wrapper is the
 * single instrumentation point for Solana RPC calls.
 */
export async function withSolanaRpc<T>(op: string, fn: () => Promise<T>): Promise<T> {
  const key = `solana_rpc:${op}`
  try {
    preCallGeneric(key)
  } catch (err) {
    if (err instanceof CircuitOpenError) {
      solanaRpcBreakerState.labels(op).set(getBreakerState(key) === 'open' ? 1 : 2)
      solanaRpcTotal.labels(op, 'circuit_open').inc()
    }
    throw err
  }
  const stateBefore = getBreakerState(key)
  const started = process.hrtime.bigint()
  let outcome = 'ok'
  try {
    const result = await fn()
    recordSuccess(key)
    solanaRpcBreakerState.labels(op).set(0)
    return result
  } catch (err) {
    outcome = classifySolanaRpcError(err)
    // Blockhash expiry is normal under load (cache stale) — don't trip
    // the breaker, but still record latency/outcome.
    if (outcome !== 'blockhash_expired') {
      recordFailure(key)
      const stateAfter = getBreakerState(key)
      solanaRpcBreakerState.labels(op).set(stateAfter === 'open' ? 1 : stateAfter === 'half-open' ? 2 : 0)
      if (stateBefore !== 'open' && stateAfter === 'open') {
        solanaRpcBreakerTripsTotal.labels(op).inc()
        logger.warn({ op }, 'Solana RPC circuit breaker tripped open')
      }
    }
    throw err
  } finally {
    const elapsed = Number(process.hrtime.bigint() - started) / 1e9
    solanaRpcDuration.labels(op, outcome).observe(elapsed)
    solanaRpcTotal.labels(op, outcome).inc()
  }
}

/**
 * Maps a Solana RPC error to a bounded Prometheus label. Keeps cardinality
 * to {ok, 429, 503, timeout, blockhash_expired, simulation_failed, other}.
 */
export function classifySolanaRpcError(err: unknown): string {
  if (!err) return 'ok'
  const msg = String((err as { message?: string }).message ?? err).toLowerCase()
  const code = (err as { code?: number }).code
  if (code === 429 || msg.includes('429') || msg.includes('rate limit')) return '429'
  if (code === 503 || msg.includes('503') || msg.includes('service unavailable')) return '503'
  if (msg.includes('timeout') || msg.includes('deadline')) return 'timeout'
  if (msg.includes('blockhash not found') || msg.includes('blockheight exceeded')) return 'blockhash_expired'
  if (msg.includes('simulation') || msg.includes('preflight')) return 'simulation_failed'
  return 'other'
}
