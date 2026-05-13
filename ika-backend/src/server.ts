import compression from 'compression'
import cors from 'cors'
import express from 'express'
import helmet from 'helmet'
import { loadConfig } from './config.js'
import { logger } from './logger.js'
import { initPool, closePool } from './store/pool.js'
import { runMigrations } from './store/migrate.js'
import { configureAuth } from './http/auth.js'
import { buildHealthRouter } from './http/healthz.js'
import { idempotencyMiddleware } from './http/idempotency.js'
import { buildEngineRouter } from './engine/routes.js'
import { closeIkaGrpcClient } from './engine/grpc-client.js'
import { buildIdentityRouter, configureIdentityLayer } from './identity/index.js'
import { buildRecoveryRouter } from './recovery/index.js'
import { buildOidcMountRouter } from './oidc/index.js'
import { startCleanupJob, stopCleanupJob } from './store/cleanup.js'
import { fail } from './types.js'
import { sanitizeError } from './safeError.js'

declare module 'http' {
  interface IncomingMessage {
    rawBody?: Buffer
  }
}

async function main(): Promise<void> {
  const config = loadConfig()

  initPool(
    config.base.databaseUrl,
    config.base.pgPoolMax,
    config.base.pgSslMode,
    config.base.pgConnectionTimeoutMillis,
  )
  await runMigrations()

  configureAuth({
    serviceApiKey: config.base.serviceApiKey,
    ...(config.base.adminApiKey ? { adminApiKey: config.base.adminApiKey } : {}),
  })

  const app = express()
  app.disable('x-powered-by')
  // Helmet enxuto: API JSON pura, sem CSP/CSRF/DNS-prefetch.
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      dnsPrefetchControl: false,
      originAgentCluster: false,
      referrerPolicy: false,
      strictTransportSecurity: { maxAge: 15_552_000, includeSubDomains: true },
      xContentTypeOptions: true,
      xFrameOptions: { action: 'deny' },
      xPoweredBy: false,
    }),
  )
  // Compressão só vale para responses > ~2KB; abaixo disso o overhead de gzip
  // supera o ganho de banda. O hot path do engine (signing) emite responses
  // pequenos, então pulamos compression nessa rota.
  app.use(
    compression({
      threshold: 2048,
      filter: (req, res) => {
        if (req.path.startsWith('/v1/dwallet')) return false
        return compression.filter(req, res)
      },
    }),
  )
  // Captura raw body para hashing determinístico no idempotency middleware
  // e para futuras rotas que precisem de payload byte-exato.
  app.use(
    express.json({
      limit: '1mb',
      verify: (req, _res, buf) => {
        if (req.headers['idempotency-key']) {
          ;(req as { rawBody?: Buffer }).rawBody = Buffer.from(buf)
        }
      },
    }),
  )
  // CORS só em rotas públicas (identity + recovery). Engine é gateway-only.
  const corsMiddleware = cors({
    origin: config.base.allowedOrigins.length > 0 ? config.base.allowedOrigins : false,
    credentials: true,
  })

  app.use(buildHealthRouter(config))

  // Defensive idempotency mirror — primary enforcement is at the gateway.
  app.use('/v1', idempotencyMiddleware())

  app.use('/v1/dwallet', buildEngineRouter(config))

  if (config.identity.enabled) {
    await configureIdentityLayer(config)
    app.use('/v1/identity', corsMiddleware, buildIdentityRouter(config))
  }

  if (config.recovery.enabled) {
    logger.info({ policyEnabled: config.recovery.policyEnabled }, 'Recovery Layer enabled')
    app.use('/v1/recovery', corsMiddleware, await buildRecoveryRouter(config))
  }

  if (config.oidc.enabled) {
    logger.info(
      { google: config.oidc.googleEnabled, apple: config.oidc.appleEnabled },
      'Login Social (OIDC) enabled',
    )
    app.use('/v1/oidc', corsMiddleware, buildOidcMountRouter(config))
  }

  app.use((req, res) => {
    res.status(404).json(fail(`Not found: ${req.method} ${req.path}`))
  })

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const safe = sanitizeError('global', err)
    res.status(500).json(fail(safe.message, safe.traceId))
  })

  const server = app.listen(config.base.port, () => {
    logger.info({ port: config.base.port, env: config.base.nodeEnv }, 'ika-backend listening')
  })

  // Cleanup job para tabelas com expires_at vencido. Roda a cada 15 min.
  startCleanupJob({ intervalMs: 15 * 60 * 1000 })

  let shuttingDown = false
  const shutdown = async (signal: string) => {
    if (shuttingDown) return
    shuttingDown = true
    logger.info({ signal }, 'shutting down')
    // Para de aceitar novos requests; aguarda os in-flight terminarem.
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) logger.warn({ err }, 'http server close error')
        else logger.info('http server closed')
        resolve()
      })
      // Garante que sockets idle não impedem o close.
      try {
        ;(server as unknown as { closeIdleConnections?: () => void }).closeIdleConnections?.()
      } catch {
        /* ignore */
      }
    })
    stopCleanupJob()
    closeIkaGrpcClient()
    await closePool()
    logger.info('shutdown complete')
    process.exit(0)
  }
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('SIGINT', () => void shutdown('SIGINT'))
}

main().catch((err) => {
  logger.fatal({ err }, 'fatal startup error')
  process.exit(1)
})
