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
  { table: 'ika_identity_email_tokens', column: 'expires_at', graceInterval: "INTERVAL '7 days'" },
  { table: 'ika_identity_oauth_states', column: 'expires_at', graceInterval: "INTERVAL '1 day'" },
  { table: 'ika_identity_passkey_challenges', column: 'expires_at', graceInterval: "INTERVAL '1 day'" },
  { table: 'ika_identity_refresh_tokens', column: 'expires_at', graceInterval: "INTERVAL '30 days'" },
  { table: 'ika_idempotency_keys', column: 'expires_at', graceInterval: "INTERVAL '1 day'" },
  { table: 'recovery_challenges', column: 'expires_at', graceInterval: "INTERVAL '7 days'" },
  // Rate log lives in a sliding 1h window; anything older than 2h is dead weight.
  { table: 'ika_identity_email_rate_log', column: 'created_at', graceInterval: "INTERVAL '2 hours'" },
  { table: 'ika_identity_email_rate_buckets', column: 'updated_at', graceInterval: "INTERVAL '2 hours'" },
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
