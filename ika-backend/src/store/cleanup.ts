// Periodic cleanup of expired rows in token / state / challenge tables.
// Keeps indexes lean and prevents unbounded growth on long-running deploys.
//
// Runs in-process via setInterval. Single instance per replica is fine —
// the queries are idempotent DELETEs and Postgres handles concurrent runs
// gracefully. For multi-replica deployments where deduplication matters,
// gate via SELECT pg_try_advisory_lock on a known key before each cycle.

import { getPool } from './pool.js'
import { logger } from '../logger.js'

interface CleanupTarget {
  readonly table: string
  readonly column: string
  /** Rows older than `expires_at + grace` are removed. */
  readonly graceInterval: string
}

const TARGETS: ReadonlyArray<CleanupTarget> = [
  { table: 'ika_idempotency_keys', column: 'expires_at', graceInterval: "INTERVAL '1 day'" },
  { table: 'recovery_challenges', column: 'expires_at', graceInterval: "INTERVAL '7 days'" },
]

let timer: NodeJS.Timeout | null = null
let running = false
const CLEANUP_ADVISORY_LOCK = 300_540_417

async function runOnce(): Promise<void> {
  if (running) return
  running = true
  const pool = getPool()
  const client = await pool.connect()
  const start = Date.now()
  let totalDeleted = 0
  try {
    const lock = await client.query<{ locked: boolean }>('SELECT pg_try_advisory_lock($1) AS locked', [
      CLEANUP_ADVISORY_LOCK,
    ])
    if (!lock.rows[0]?.locked) return
    try {
      for (const t of TARGETS) {
        try {
          const result = await client.query(
            `DELETE FROM ${t.table} WHERE ${t.column} < NOW() - ${t.graceInterval}`,
          )
          const deleted = result.rowCount ?? 0
          totalDeleted += deleted
          if (deleted > 0) {
            logger.info({ table: t.table, deleted }, 'cleanup: removed expired rows')
          }
        } catch (err) {
          logger.warn({ err, table: t.table }, 'cleanup: query failed (swallowed)')
        }
      }
      // P0.1: orphaned idempotency reservations. A replica that crashed
      // mid-mutation leaves a row at status='in_progress' whose
      // reservation_until has elapsed. The takeover path in the middleware
      // already handles new requests racing for the same key, but the row
      // can otherwise sit around until the 24h `expires_at`. Clear it
      // sooner so the table stays small and the next legitimate retry
      // sees a fresh INSERT instead of a takeover.
      try {
        const stale = await client.query(
          `DELETE FROM ika_idempotency_keys
             WHERE status = 'in_progress'
               AND reservation_until IS NOT NULL
               AND reservation_until < NOW() - INTERVAL '5 minutes'`,
        )
        const stuck = stale.rowCount ?? 0
        if (stuck > 0) {
          logger.warn({ stuck }, 'cleanup: removed abandoned idempotency reservations')
          totalDeleted += stuck
        }
      } catch (err) {
        logger.warn({ err }, 'cleanup: stale-reservation sweep failed (swallowed)')
      }
    } finally {
      await client.query('SELECT pg_advisory_unlock($1)', [CLEANUP_ADVISORY_LOCK]).catch(() => {})
    }
    if (totalDeleted > 0) {
      logger.info({ totalDeleted, durationMs: Date.now() - start }, 'cleanup cycle complete')
    }
  } finally {
    client.release()
    running = false
  }
}

export interface CleanupOptions {
  readonly intervalMs: number
}

export function startCleanupJob(opts: CleanupOptions): void {
  if (timer) return
  // Run once after a short delay so the first cycle does not race with boot.
  const initial = setTimeout(() => {
    void runOnce()
  }, 60_000)
  initial.unref()
  timer = setInterval(() => {
    void runOnce()
  }, opts.intervalMs)
  timer.unref()
  logger.info({ intervalMs: opts.intervalMs, targets: TARGETS.length }, 'cleanup job started')
}

export function stopCleanupJob(): void {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}
