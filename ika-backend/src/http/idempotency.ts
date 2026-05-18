/**
 * Cross-replica atomic Idempotency-Key middleware for the engine layer.
 *
 * P0.1 of the robustness plan: before *anything* the gateway/client can retry
 * runs twice, the middleware claims the key atomically in Postgres so two
 * replicas receiving the same key concurrently cannot both execute the
 * mutation. The claim is a modifying CTE — one round-trip, no SELECT-then-
 * UPDATE race window.
 *
 * Wire format (mirrors the gateway):
 *   - request  : `Idempotency-Key` header
 *   - replay   : original status + body + headers + `Idempotent-Replay: true`
 *   - collision: 422 `idempotency_collision` (body mismatch)
 *   - inflight : 409 `idempotency_in_progress` (another replica still running)
 *
 * Schema (see `migrations/016_idempotency_atomic.sql`):
 *   status ∈ {'in_progress', 'completed'}
 *   reservation_id     : per-attempt UUID — only the owner can finalize.
 *   reservation_until  : absolute deadline; crashed replicas leak no rows
 *                        because `reservation_until` passes and another
 *                        replica can take over via UPDATE.
 *
 * Failure-open posture: a Postgres outage that prevents the reservation
 * is logged and the request proceeds (request still goes through the
 * gateway's primary idempotency layer). The hot path of a Postgres
 * outage already loses other features anyway.
 */

import type { NextFunction, Request, Response } from 'express'
import { createHash, randomUUID } from 'node:crypto'
import { getPool } from '../store/pool.js'
import { logger } from '../logger.js'
import { idempotencyConflicts, idempotencyHits, idempotencyMisses } from '../metrics.js'

export const HEADER_NAME = 'idempotency-key'
export const REPLAY_HEADER = 'Idempotent-Replay'

const DEFAULT_TTL_HOURS = 24
const RESERVATION_TTL_SECONDS = 60 // hard ceiling on how long a single mutation may hold the key
const MAX_BODY_BYTES = 1 * 1024 * 1024
const MAX_RESPONSE_BYTES = 256 * 1024
const SCOPE = 'ika'

const L1_CACHE_CAP = 2048

interface CachedEntry {
  status_code: number
  response_body: Buffer
  response_headers: Record<string, string>
  request_hash: string
  expires_at: number
}

const l1Cache = new Map<string, CachedEntry>()

function l1Key(apiKeyId: string, methodPath: string, idemKey: string): string {
  return `${apiKeyId}|${methodPath}|${idemKey}`
}

function l1Get(key: string): CachedEntry | null {
  const entry = l1Cache.get(key)
  if (!entry) return null
  if (entry.expires_at <= Date.now()) {
    l1Cache.delete(key)
    return null
  }
  l1Cache.delete(key)
  l1Cache.set(key, entry)
  return entry
}

function l1Set(key: string, entry: CachedEntry): void {
  if (l1Cache.has(key)) l1Cache.delete(key)
  l1Cache.set(key, entry)
  if (l1Cache.size > L1_CACHE_CAP) {
    const oldest = l1Cache.keys().next().value
    if (oldest !== undefined) l1Cache.delete(oldest)
  }
}

function shouldApply(method: string): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())
}

function requestPath(req: Request): string {
  return (req.originalUrl.split('?')[0] ?? req.originalUrl).replace(/\/+$/, '')
}

/**
 * Routes that MUST carry an Idempotency-Key. P0.1 of the robustness plan
 * promotes the original `/submit` cover to every gas-sponsored or MPC
 * mutation so a duplicate Solana transaction is impossible by construction.
 */
function requiresIdempotencyKey(req: Request): boolean {
  if (!shouldApply(req.method)) return false
  const path = requestPath(req)
  if (!path.startsWith('/v1/dwallet/')) return false
  if (path.endsWith('/submit')) return true
  // MCP wallet API + transfer-ownership are gas-sponsored Solana submits.
  if (path === '/v1/dwallet/create') return true
  if (path === '/v1/dwallet/transfer-ownership') return true
  if (path === '/v1/dwallet/presign') return true
  if (path === '/v1/dwallet/sign') return true
  return false
}

function hashBody(buf: Buffer | undefined): string {
  if (!buf || buf.length === 0) return ''
  return createHash('sha256').update(buf).digest('hex')
}

function hashApiKeyId(apiKey: string): string {
  if (!apiKey) return 'anon'
  return createHash('sha256').update(apiKey, 'utf8').digest('hex').slice(0, 32)
}

function getRawBodyBuffer(req: Request): Buffer {
  const raw = (req as { rawBody?: Buffer }).rawBody
  if (raw && raw.length > 0) return raw
  if (req.body === undefined || req.body === null) return Buffer.alloc(0)
  if (typeof req.body === 'string') return Buffer.from(req.body, 'utf8')
  if (Buffer.isBuffer(req.body)) return req.body
  try {
    return Buffer.from(JSON.stringify(req.body), 'utf8')
  } catch {
    return Buffer.alloc(0)
  }
}

interface ReservationRow {
  reservation_id: string
  status: 'in_progress' | 'completed'
  request_hash: string
  status_code: number | null
  response_body: Buffer | null
  response_headers: Record<string, string> | null
  reservation_until: Date | null
  expires_at: Date
  did_reserve: boolean
}

/**
 * One round-trip reservation. Returns the canonical row for the key:
 *
 *   - When we successfully reserved (insert OR takeover), `did_reserve=true`
 *     and the row's reservation_id matches ours.
 *   - When the key was already completed, `did_reserve=false` and the row
 *     carries status_code / response_body / response_headers.
 *   - When another replica is mid-flight, `did_reserve=false`,
 *     status='in_progress', reservation_until in the future.
 *
 * Returns null on Postgres error — caller fails open.
 */
async function reserveOrLookup(args: {
  apiKeyId: string
  methodPath: string
  idemKey: string
  requestHash: string
  reservationId: string
  expiresAt: Date
}): Promise<ReservationRow | null> {
  const pool = getPool()
  try {
    const { rows } = await pool.query<ReservationRow>(
      `
      WITH ins AS (
        INSERT INTO ika_idempotency_keys
          (scope, api_key_id, method_path, idem_key, request_hash, status,
           reserved_at, reservation_id,
           reservation_until,
           expires_at)
        VALUES
          ($1, $2, $3, $4, $5, 'in_progress',
           NOW(), $6,
           NOW() + ($7::int * INTERVAL '1 second'),
           $8)
        ON CONFLICT (scope, api_key_id, method_path, idem_key) DO NOTHING
        RETURNING reservation_id, status, request_hash, status_code,
                  response_body, response_headers, reservation_until, expires_at,
                  TRUE AS did_reserve
      ),
      takeover AS (
        UPDATE ika_idempotency_keys
        SET status            = 'in_progress',
            reserved_at       = NOW(),
            reservation_id    = $6,
            reservation_until = NOW() + ($7::int * INTERVAL '1 second'),
            request_hash      = $5,
            status_code       = NULL,
            response_body     = NULL,
            response_headers  = NULL,
            expires_at        = $8
        WHERE scope = $1 AND api_key_id = $2 AND method_path = $3 AND idem_key = $4
          AND status = 'in_progress'
          AND reservation_until <= NOW()
          AND NOT EXISTS (SELECT 1 FROM ins)
        RETURNING reservation_id, status, request_hash, status_code,
                  response_body, response_headers, reservation_until, expires_at,
                  TRUE AS did_reserve
      ),
      existing AS (
        SELECT reservation_id, status, request_hash, status_code,
               response_body, response_headers, reservation_until, expires_at,
               FALSE AS did_reserve
        FROM ika_idempotency_keys
        WHERE scope = $1 AND api_key_id = $2 AND method_path = $3 AND idem_key = $4
          AND expires_at > NOW()
          AND NOT EXISTS (SELECT 1 FROM ins)
          AND NOT EXISTS (SELECT 1 FROM takeover)
      )
      SELECT * FROM ins
      UNION ALL
      SELECT * FROM takeover
      UNION ALL
      SELECT * FROM existing
      `,
      [SCOPE, args.apiKeyId, args.methodPath, args.idemKey, args.requestHash, args.reservationId, RESERVATION_TTL_SECONDS, args.expiresAt],
    )
    if (rows.length === 0) {
      // Existing row was expired but cleanup hadn't deleted it yet, and the
      // CTE didn't observe it: extremely rare. Caller will retry the
      // reservation on the next request rather than complicate this path.
      return null
    }
    return rows[0] ?? null
  } catch (err) {
    logger.warn({ err }, 'idempotency reservation query failed')
    return null
  }
}

/** Persists the final response body and flips status → 'completed'.
 *  Only updates if the row still carries our reservation_id, so a stale
 *  finalize after takeover cannot overwrite a fresh attempt's result. */
async function finalizeReservation(args: {
  apiKeyId: string
  methodPath: string
  idemKey: string
  reservationId: string
  statusCode: number
  body: Buffer
  headers: Record<string, string>
  expiresAt: Date
}): Promise<void> {
  const pool = getPool()
  await pool.query(
    `
    UPDATE ika_idempotency_keys
    SET status            = 'completed',
        status_code       = $5,
        response_body     = $6,
        response_headers  = $7::jsonb,
        reservation_until = NULL,
        expires_at        = $8
    WHERE scope = $1 AND api_key_id = $2 AND method_path = $3 AND idem_key = $4
      AND reservation_id = $9
    `,
    [SCOPE, args.apiKeyId, args.methodPath, args.idemKey, args.statusCode, args.body, JSON.stringify(args.headers), args.expiresAt, args.reservationId],
  )
}

/** Releases the reservation on a 5xx so the next client retry is allowed
 *  to re-execute the mutation. We DELETE the row (rather than mark
 *  expired) so cleanup doesn't have to wait for the TTL grace window. */
async function releaseReservation(args: {
  apiKeyId: string
  methodPath: string
  idemKey: string
  reservationId: string
}): Promise<void> {
  const pool = getPool()
  await pool.query(
    `DELETE FROM ika_idempotency_keys
     WHERE scope = $1 AND api_key_id = $2 AND method_path = $3 AND idem_key = $4
       AND reservation_id = $5`,
    [SCOPE, args.apiKeyId, args.methodPath, args.idemKey, args.reservationId],
  )
}

export function idempotencyMiddleware() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!shouldApply(req.method)) {
      next()
      return
    }
    const headerValue = req.header(HEADER_NAME)
    const idemKey = headerValue ? headerValue.trim() : ''
    if (!idemKey) {
      if (requiresIdempotencyKey(req)) {
        res.status(428).json({
          error: {
            code: 'idempotency_key_required',
            message: 'Idempotency-Key is required for this mutation',
          },
        })
        return
      }
      next()
      return
    }
    if (idemKey.length < 8 || idemKey.length > 200) {
      res.status(400).json({
        error: { code: 'invalid_idempotency_key', message: 'Idempotency-Key must be 8-200 chars' },
      })
      return
    }

    const bodyBuf = getRawBodyBuffer(req)
    if (bodyBuf.length > MAX_BODY_BYTES) {
      res.status(400).json({
        error: { code: 'body_too_large', message: 'request body exceeds idempotency hash limit' },
      })
      return
    }
    const requestHash = hashBody(bodyBuf)

    const apiKeyId = hashApiKeyId(req.header('x-api-key') ?? req.header('x-service-api-key') ?? '')
    const methodPath = `${req.method.toUpperCase()} ${req.path}`
    const cacheKey = l1Key(apiKeyId, methodPath, idemKey)

    // L1 — only stores completed responses, so an L1 hit always replays.
    const l1Hit = l1Get(cacheKey)
    if (l1Hit) {
      idempotencyHits.inc()
      if (l1Hit.request_hash !== requestHash) {
        idempotencyConflicts.inc()
        res.status(422).json({
          error: {
            code: 'idempotency_collision',
            message: 'Idempotency-Key reused with a different request body',
          },
        })
        return
      }
      for (const [k, v] of Object.entries(l1Hit.response_headers)) {
        const lk = k.toLowerCase()
        if (lk === 'content-length' || lk === 'transfer-encoding') continue
        res.setHeader(k, v)
      }
      res.setHeader(REPLAY_HEADER, 'true')
      res.status(l1Hit.status_code).send(l1Hit.response_body)
      return
    }

    const reservationId = randomUUID()
    const expiresAt = new Date(Date.now() + DEFAULT_TTL_HOURS * 3600 * 1000)

    const reservation = await reserveOrLookup({
      apiKeyId,
      methodPath,
      idemKey,
      requestHash,
      reservationId,
      expiresAt,
    })

    if (reservation === null) {
      // Postgres failed — fail open. Gateway's idempotency layer is the
      // primary defense; this middleware is the defensive mirror.
      next()
      return
    }

    if (!reservation.did_reserve) {
      // Someone got there first.
      if (reservation.status === 'completed' && reservation.response_body !== null && reservation.status_code !== null) {
        idempotencyHits.inc()
        if (reservation.request_hash !== requestHash) {
          idempotencyConflicts.inc()
          res.status(422).json({
            error: {
              code: 'idempotency_collision',
              message: 'Idempotency-Key reused with a different request body',
            },
          })
          return
        }
        const headers = reservation.response_headers ?? {}
        l1Set(cacheKey, {
          status_code: reservation.status_code,
          response_body: reservation.response_body,
          response_headers: headers,
          request_hash: reservation.request_hash,
          expires_at: reservation.expires_at.getTime(),
        })
        for (const [k, v] of Object.entries(headers)) {
          const lk = k.toLowerCase()
          if (lk === 'content-length' || lk === 'transfer-encoding') continue
          res.setHeader(k, v)
        }
        res.setHeader(REPLAY_HEADER, 'true')
        res.status(reservation.status_code).send(reservation.response_body)
        return
      }
      // status='in_progress' on a fresh reservation we don't own.
      if (reservation.request_hash !== requestHash) {
        idempotencyConflicts.inc()
        res.status(422).json({
          error: {
            code: 'idempotency_collision',
            message: 'Idempotency-Key reused with a different request body',
          },
        })
        return
      }
      // Tell the caller to back off and retry; the original attempt may
      // finish meanwhile and the next retry will replay its response.
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil(((reservation.reservation_until?.getTime() ?? Date.now()) - Date.now()) / 1000),
      )
      res.setHeader('Retry-After', String(retryAfterSeconds))
      res.status(409).json({
        error: {
          code: 'idempotency_in_progress',
          message: 'Another request with this Idempotency-Key is still in progress',
        },
      })
      return
    }

    // We hold the reservation. Capture the response and finalize on end().
    idempotencyMisses.inc()
    const chunks: Buffer[] = []
    const originalWrite = res.write.bind(res) as (...args: unknown[]) => boolean
    const originalEnd = res.end.bind(res) as (...args: unknown[]) => Response
    let finalized = false

    res.write = ((chunk: unknown, ...args: unknown[]): boolean => {
      if (typeof chunk === 'string') chunks.push(Buffer.from(chunk, 'utf8'))
      else if (chunk instanceof Buffer) chunks.push(chunk)
      else if (chunk instanceof Uint8Array) chunks.push(Buffer.from(chunk))
      return originalWrite(chunk as never, ...(args as never[]))
    }) as typeof res.write

    res.end = ((chunk?: unknown, ...args: unknown[]): Response => {
      if (chunk !== undefined) {
        if (typeof chunk === 'string') chunks.push(Buffer.from(chunk, 'utf8'))
        else if (chunk instanceof Buffer) chunks.push(chunk)
        else if (chunk instanceof Uint8Array) chunks.push(Buffer.from(chunk))
      }
      const body = Buffer.concat(chunks)
      const statusCode = res.statusCode
      if (!finalized) {
        finalized = true
        // 5xx: release the reservation so the next client retry is allowed
        // to re-execute. 4xx and 2xx are persisted as the canonical reply.
        if (statusCode >= 500) {
          releaseReservation({ apiKeyId, methodPath, idemKey, reservationId }).catch((err) =>
            logger.warn({ err }, 'idempotency release failed'),
          )
        } else if (body.length <= MAX_RESPONSE_BYTES) {
          const headers: Record<string, string> = {}
          for (const k of Object.keys(res.getHeaders())) {
            const v = res.getHeader(k)
            if (typeof v === 'string') headers[k] = v
            else if (typeof v === 'number') headers[k] = String(v)
          }
          l1Set(cacheKey, {
            status_code: statusCode,
            response_body: body,
            response_headers: headers,
            request_hash: requestHash,
            expires_at: expiresAt.getTime(),
          })
          finalizeReservation({
            apiKeyId,
            methodPath,
            idemKey,
            reservationId,
            statusCode,
            body,
            headers,
            expiresAt,
          }).catch((err) => logger.warn({ err }, 'idempotency finalize failed'))
        } else {
          logger.warn(
            { statusCode, responseBytes: body.length, maxResponseBytes: MAX_RESPONSE_BYTES, methodPath },
            'idempotency response too large; releasing reservation',
          )
          releaseReservation({ apiKeyId, methodPath, idemKey, reservationId }).catch((err) =>
            logger.warn({ err }, 'idempotency release failed'),
          )
        }
      }
      return originalEnd(chunk as never, ...(args as never[]))
    }) as typeof res.end

    next()
  }
}
