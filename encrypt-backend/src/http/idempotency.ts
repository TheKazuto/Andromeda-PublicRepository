/**
 * Atomic cross-replica Idempotency-Key middleware for encrypt-backend.
 *
 * P0.1 of the robustness plan: the gateway is the primary enforcement
 * layer, but this middleware is the last line of defence inside the
 * private network. Two replicas receiving the same Idempotency-Key
 * concurrently must not both call `sendTransaction` — one duplicate
 * Solana submit is one duplicate gas spend.
 *
 * Strategy:
 *   1. SHA-256 the request body and derive a deterministic Redis key
 *      from (scope, api_key_id, method+path, idem_key).
 *   2. Look up the completion cache first (`idem:cache:...`). On hit
 *      with matching body hash → replay; mismatch → 422.
 *   3. Otherwise claim a short-lived in-flight lock (`idem:lock:...`)
 *      via SET NX PX. Failure to acquire → 409 in_progress with
 *      Retry-After hint.
 *   4. Run the handler, then write the completion cache (long TTL) and
 *      release the lock. On 5xx the lock is released so the client can
 *      legitimately retry; on 2xx/4xx the cache replays the response.
 *
 * Fail-closed posture: when `requireIdempotencyLock` is true (default
 * in production) and Redis is unreachable on a route that mandates an
 * Idempotency-Key, the middleware returns 503 — better to refuse a
 * mutation than to risk duplicate execution.
 */

import type { Context, MiddlewareHandler } from 'hono'
import { createHash, randomUUID } from 'node:crypto'

import {
  cacheDel,
  cacheGet,
  cacheSet,
  cacheSetNX,
} from '../cache/redis.js'
import { logger } from '../lib/logger.js'
import { config, isCacheEnabled, requireIdempotencyLock } from '../config.js'
import {
  idempotencyConflicts,
  idempotencyHits,
  idempotencyMisses,
} from '../lib/metrics.js'

const HEADER = 'idempotency-key'
const REPLAY_HEADER = 'Idempotent-Replay'
const COMPLETION_TTL_SECONDS = 24 * 60 * 60
const LOCK_TTL_SECONDS = 60
const SCOPE = 'encrypt'

interface CachedEntry {
  status: number
  body: string
  contentType: string
  requestHash: string
}

interface InflightEntry {
  requestHash: string
  reservationId: string
  expiresAtMs: number
}

function shouldApply(method: string): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())
}

function hashBody(buf: Uint8Array): string {
  if (buf.length === 0) return ''
  return createHash('sha256').update(buf).digest('hex')
}

/**
 * Routes that MUST carry an Idempotency-Key. encrypt-backend is mostly
 * a prepare/submit engine; the dangerous mutation is the `/submit` path
 * that pushes a signed transaction to Solana, plus NEK rotation. Other
 * `/prepare` endpoints can be retried safely (they only compute an
 * unsigned tx) but still benefit from de-dup when the caller provides
 * a key.
 */
function requiresIdempotencyKey(c: Context): boolean {
  if (!shouldApply(c.req.method)) return false
  const path = new URL(c.req.url).pathname
  if (path.endsWith('/submit')) return true
  if (path === '/v1/nek/override' || path === '/v1/nek/authorize') return true
  return false
}

function lockKey(apiKeyId: string, methodPath: string, idemKey: string): string {
  return `idem:lock:${SCOPE}:${apiKeyId}:${methodPath}:${idemKey}`
}

function cacheKeyFor(apiKeyId: string, methodPath: string, idemKey: string): string {
  return `idem:cache:${SCOPE}:${apiKeyId}:${methodPath}:${idemKey}`
}

export const idempotencyMiddleware: MiddlewareHandler = async (c: Context, next) => {
  if (!shouldApply(c.req.method)) {
    return next()
  }
  const headerValue = c.req.header(HEADER)
  const idemKey = headerValue ? headerValue.trim() : ''
  const isRequired = requiresIdempotencyKey(c)

  if (!idemKey) {
    if (isRequired) {
      return c.json(
        {
          error: {
            code: 'idempotency_key_required',
            message: 'Idempotency-Key is required for this mutation',
          },
        },
        428,
      )
    }
    return next()
  }
  if (idemKey.length < 8 || idemKey.length > 200) {
    return c.json(
      {
        error: { code: 'invalid_idempotency_key', message: 'Idempotency-Key must be 8-200 chars' },
      },
      400,
    )
  }

  // When the route requires a key but Redis is offline AND we are in a
  // fail-closed posture (production default), refuse the mutation. The
  // gateway's idempotency layer is the primary line, but if this engine
  // is reached directly while Redis is gone there is no defence at all.
  if (isRequired && requireIdempotencyLock && !isCacheEnabled) {
    return c.json(
      {
        error: {
          code: 'idempotency_unavailable',
          message: 'Idempotency backend is required for this route but not configured',
        },
      },
      503,
    )
  }

  const apiKeyId = createHash('sha256')
    .update(c.req.header('x-internal-key') ?? 'anon')
    .digest('hex')
    .slice(0, 24)
  const methodPath = `${c.req.method.toUpperCase()} ${new URL(c.req.url).pathname}`
  const lock = lockKey(apiKeyId, methodPath, idemKey)
  const cacheKey = cacheKeyFor(apiKeyId, methodPath, idemKey)

  let bodyBuf: Uint8Array
  try {
    bodyBuf = new Uint8Array(await c.req.raw.clone().arrayBuffer())
  } catch {
    bodyBuf = new Uint8Array(0)
  }
  if (bodyBuf.byteLength > config.MAX_BODY_BYTES) {
    return c.json(
      { error: { code: 'body_too_large', message: 'request body exceeds idempotency hash limit' } },
      400,
    )
  }
  const requestHash = hashBody(bodyBuf)

  // 1. Completion cache hit → replay (no lock needed).
  const cached = await cacheGet<CachedEntry>(cacheKey)
  if (cached) {
    idempotencyHits.inc()
    if (cached.requestHash !== requestHash) {
      idempotencyConflicts.inc()
      return c.json(
        {
          error: {
            code: 'idempotency_collision',
            message: 'Idempotency-Key reused with a different request body',
          },
        },
        422,
      )
    }
    c.header(REPLAY_HEADER, 'true')
    c.header('content-type', cached.contentType || 'application/json')
    return c.body(cached.body, cached.status as 200 | 201 | 202 | 400 | 404 | 422)
  }

  // 2. Try to acquire the in-flight lock atomically.
  const reservationId = randomUUID()
  const inflightPayload: InflightEntry = {
    requestHash,
    reservationId,
    expiresAtMs: Date.now() + LOCK_TTL_SECONDS * 1000,
  }
  const acquired = await cacheSetNX(lock, inflightPayload, LOCK_TTL_SECONDS)

  if (acquired === null) {
    // Redis unavailable / disabled. Required routes already short-
    // circuited above; for optional routes we fail open so dev stacks
    // without Redis keep working.
    idempotencyMisses.inc()
    return next()
  }

  if (acquired === false) {
    // Another replica already holds the lock. Compare hashes to surface
    // collisions even mid-flight; otherwise tell the client to retry.
    const inflight = await cacheGet<InflightEntry>(lock)
    if (inflight && inflight.requestHash !== requestHash) {
      idempotencyConflicts.inc()
      return c.json(
        {
          error: {
            code: 'idempotency_collision',
            message: 'Idempotency-Key reused with a different request body',
          },
        },
        422,
      )
    }
    const retryAfter = Math.max(
      1,
      Math.ceil(((inflight?.expiresAtMs ?? Date.now()) - Date.now()) / 1000),
    )
    c.header('Retry-After', String(retryAfter))
    return c.json(
      {
        error: {
          code: 'idempotency_in_progress',
          message: 'Another request with this Idempotency-Key is still in progress',
        },
      },
      409,
    )
  }

  // 3. We hold the lock — run the handler.
  idempotencyMisses.inc()
  try {
    await next()
  } catch (err) {
    // Release immediately on uncaught error so the next retry can take over.
    await cacheDel(lock).catch(() => undefined)
    throw err
  }

  const status = c.res.status
  if (status >= 500) {
    // 5xx: release the lock so the client can legitimately retry.
    await cacheDel(lock).catch((err) =>
      logger.warn({ err, lock }, 'idempotency lock release failed'),
    )
    return
  }

  // 4. Persist the completion + release the lock. cacheSet errors are
  // swallowed because the response has already been written; we log so
  // ops can correlate replay misses with Redis incidents.
  try {
    const cloned = c.res.clone()
    const body = await cloned.text()
    const contentType = cloned.headers.get('content-type') ?? 'application/json'
    const entry: CachedEntry = { status, body, contentType, requestHash }
    await cacheSet(cacheKey, entry, COMPLETION_TTL_SECONDS)
  } catch (err) {
    logger.warn({ err, cacheKey }, 'idempotency persist failed')
  }
  await cacheDel(lock).catch(() => undefined)
}
