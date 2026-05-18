import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getPool } from './pool.js'
import { logger } from '../logger.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const MIGRATIONS_DIR = join(__dirname, 'migrations')

// Stable advisory-lock key for the migration runner. Two replicas booting
// at the same time both try to claim this key inside a transaction; the
// loser blocks until the winner commits and then sees the migrations as
// already applied. Generated once and kept constant.
const MIGRATION_ADVISORY_LOCK_KEY = 0x416e_6472_6f6d_4d69n // 'AndroMi'

/**
 * Apply pending migrations.
 *
 * P0.2: every replica calls runMigrations() on boot. To prevent races
 * (`relation already exists`, half-applied schemas, duplicate-key in
 * schema_migrations) we wrap the apply loop in a single transaction
 * guarded by `pg_advisory_xact_lock`. The lock releases automatically
 * on COMMIT/ROLLBACK, so a crashed replica can't keep it forever.
 *
 * The lock is taken on a dedicated client (`pool.connect()`) so the
 * transactional advisory lock is bound to the same backend that runs
 * the migrations — required for transactional advisory locks to behave
 * correctly under PgBouncer in transaction-pooling mode.
 */
export async function runMigrations(): Promise<void> {
  const pool = getPool()
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    // Wait for the lock — pg_advisory_xact_lock blocks until acquired,
    // then releases on commit/rollback. Two booting replicas serialise
    // here instead of racing on schema DDL.
    await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATION_ADVISORY_LOCK_KEY])

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        filename TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `)

    const files = readdirSync(MIGRATIONS_DIR)
      .filter((f) => f.endsWith('.sql'))
      .sort()

    for (const file of files) {
      const { rowCount } = await client.query('SELECT 1 FROM schema_migrations WHERE filename = $1', [file])
      if (rowCount && rowCount > 0) continue

      const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8')
      logger.info({ file }, 'applying migration')
      await client.query(sql)
      // ON CONFLICT DO NOTHING: defends against a concurrent run that
      // released the lock and reapplied between SELECT and INSERT (only
      // possible if pg_advisory_xact_lock somehow returned early — keep
      // as belt-and-braces).
      await client.query(
        'INSERT INTO schema_migrations(filename) VALUES ($1) ON CONFLICT DO NOTHING',
        [file],
      )
    }

    await client.query('COMMIT')
  } catch (err) {
    try {
      await client.query('ROLLBACK')
    } catch (rollbackErr) {
      logger.error({ err: rollbackErr }, 'migration rollback failed; surfacing original error')
    }
    throw err
  } finally {
    client.release()
  }

  logger.info('migrations complete')
}
