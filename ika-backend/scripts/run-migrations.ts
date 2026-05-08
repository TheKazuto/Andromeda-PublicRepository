import { loadConfig } from '../src/config.js'
import { initPool, closePool } from '../src/store/pool.js'
import { runMigrations } from '../src/store/migrate.js'
import { logger } from '../src/logger.js'

async function main(): Promise<void> {
  const config = loadConfig()
  initPool(config.base.databaseUrl, config.base.pgPoolMax, config.base.pgSslMode)
  await runMigrations()
  await closePool()
  logger.info('migrations done')
}

main().catch((err) => {
  logger.fatal({ err }, 'migration failure')
  process.exit(1)
})
