// Production migration runner — compiled to `dist/cmd/migrate.js` so it works
// in the runtime container (which has no devDependencies, so no `tsx`).
//
// Run with: `npm run migrate` (= `node dist/cmd/migrate.js`). On Railway,
// wire this as a release command (or run it once via the service shell).
// For local dev with hot-reload sources, `npm run migrate:dev` uses tsx.

import { loadConfig } from '../config.js'
import { initPool, closePool } from '../store/pool.js'
import { runMigrations } from '../store/migrate.js'
import { logger } from '../logger.js'

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
