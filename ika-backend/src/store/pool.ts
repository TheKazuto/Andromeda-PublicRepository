import pg from 'pg'
import { logger } from '../logger.js'

const { Pool } = pg

let pool: pg.Pool | null = null

/**
 * Initialise the node-postgres pool.
 *
 * Pool sizing knobs (env, all optional — see config.ts for the defaults
 * passed in by `initPool` callers):
 *
 *   PG_POOL_MAX                — pool ceiling
 *   PG_POOL_IDLE_TIMEOUT_MS    — kill idle conns after N ms (default 30000)
 *   PG_CONNECTION_TIMEOUT_MS   — Acquire() timeout (default 3000)
 *   PG_STATEMENT_TIMEOUT_MS    — Postgres `statement_timeout` (default 30000)
 *   PG_IDLE_IN_TX_TIMEOUT_MS   — `idle_in_transaction_session_timeout` (default 60000)
 *
 * PgBouncer note: in transaction-pool mode the pg driver must not use
 * named prepared statements across statements. This pool already uses
 * unnamed queries (`pool.query(text, params)`); the idempotency
 * middleware was updated to drop `name:` from its queries for the same
 * reason. If you wire new code that uses `client.query({ name, text })`,
 * keep the `name` empty under PgBouncer.
 */
export function initPool(
  databaseUrl: string,
  max = 20,
  sslMode: string | undefined = 'prefer',
  connectionTimeoutMillis = 3_000,
): pg.Pool {
  if (pool) return pool
  const ssl =
    sslMode === 'require' || sslMode === 'verify-full'
      ? { rejectUnauthorized: sslMode === 'verify-full' }
      : sslMode === 'disable'
        ? false
        : undefined
  const idleTimeoutMs = Number(process.env.PG_POOL_IDLE_TIMEOUT_MS ?? '30000')
  const stmtTimeoutMs = Number(process.env.PG_STATEMENT_TIMEOUT_MS ?? '30000')
  const idleTxTimeoutMs = Number(process.env.PG_IDLE_IN_TX_TIMEOUT_MS ?? '60000')

  pool = new Pool({
    connectionString: databaseUrl,
    max,
    idleTimeoutMillis: Number.isFinite(idleTimeoutMs) ? idleTimeoutMs : 30_000,
    connectionTimeoutMillis,
    ...(ssl !== undefined ? { ssl } : {}),
  })

  // Apply session timeouts on every new connection. node-postgres emits
  // `connect` once per client lifetime (not per Acquire), so this is
  // amortised across the pool.
  pool.on('connect', (client) => {
    const setters: Array<Promise<unknown>> = []
    if (Number.isFinite(stmtTimeoutMs) && stmtTimeoutMs > 0) {
      setters.push(client.query(`SET statement_timeout = ${Math.floor(stmtTimeoutMs)}`))
    }
    if (Number.isFinite(idleTxTimeoutMs) && idleTxTimeoutMs > 0) {
      setters.push(client.query(`SET idle_in_transaction_session_timeout = ${Math.floor(idleTxTimeoutMs)}`))
    }
    Promise.all(setters).catch((err) => {
      logger.warn({ err }, 'pg: failed to apply session timeouts')
    })
  })

  pool.on('error', (err) => {
    logger.error({ err }, 'pg pool error')
  })
  return pool
}

export function getPool(): pg.Pool {
  if (!pool) throw new Error('Postgres pool not initialized')
  return pool
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end()
    pool = null
  }
}

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<pg.QueryResult<T>> {
  return getPool().query<T>(text, params)
}

export async function withTransaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    // Always re-throw the *original* failure — a ROLLBACK that itself fails
    // (e.g. the connection dropped) must not mask why the transaction failed.
    try {
      await client.query('ROLLBACK')
    } catch (rollbackErr) {
      logger.error({ err: rollbackErr }, 'withTransaction: ROLLBACK failed; surfacing the original error')
    }
    throw err
  } finally {
    client.release()
  }
}
