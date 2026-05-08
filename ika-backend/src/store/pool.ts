import pg from 'pg'
import { logger } from '../logger.js'

const { Pool } = pg

let pool: pg.Pool | null = null

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
  pool = new Pool({
    connectionString: databaseUrl,
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis,
    ...(ssl !== undefined ? { ssl } : {}),
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
    await client.query('ROLLBACK')
    throw err
  } finally {
    client.release()
  }
}
