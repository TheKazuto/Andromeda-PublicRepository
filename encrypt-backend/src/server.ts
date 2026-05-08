import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { bodyLimit } from 'hono/body-limit';
import { serve } from '@hono/node-server';

import { config } from './config.js';
import { logger } from './lib/logger.js';
import { toApiError } from './lib/errors.js';
import { internalKeyMiddleware } from './auth/internalKey.js';
import { idempotencyMiddleware } from './http/idempotency.js';
import { initOperationRegistry } from './dsl/operations.js';
import { preWarmEncryptClient } from './encrypt/client.js';

import { publicHealthRoutes, deepHealthRoutes } from './routes/health.routes.js';
import { ciphertextRoutes } from './routes/ciphertext.routes.js';
import { graphRoutes } from './routes/graph.routes.js';
import { dslRoutes } from './routes/dsl.routes.js';
import { walletRoutes } from './routes/wallet.routes.js';
import { transactionRoutes } from './routes/transaction.routes.js';
import { decryptRoutes } from './routes/decrypt.routes.js';
import { nekRoutes } from './routes/nek.routes.js';
import { eventsRoutes } from './routes/events.routes.js';
import { authorityRoutes } from './routes/authority.routes.js';
import { feesRoutes } from './routes/fees.routes.js';
import { ownershipRoutes } from './routes/ownership.routes.js';
import { decisionRoutes } from './routes/decision.routes.js';

initOperationRegistry();
// Fire-and-forget pre-warm of the gRPC client so the first user request does
// not pay the dynamic import + handshake cost.
void preWarmEncryptClient();

const app = new Hono();

app.use('*', async (c, next) => {
  const started = Date.now();
  await next();
  if (!c.req.path.startsWith('/health')) {
    logger.info(
      {
        method: c.req.method,
        path: c.req.path,
        status: c.res.status,
        durationMs: Date.now() - started,
      },
      'request complete'
    );
  }
});
app.use('*', secureHeaders());

// Restrict CORS. Empty allowlist in production = no cross-origin allowed
// (service is meant to be private). `*` only kept for local dev convenience.
const allowedOrigins = config.ALLOWED_ORIGINS;
const corsOriginConfig: '*' | string[] =
  allowedOrigins.includes('*')
    ? '*'
    : allowedOrigins.length > 0
      ? allowedOrigins
      : config.NODE_ENV === 'development'
        ? '*'
        : [];

app.use(
  '*',
  cors({
    origin: corsOriginConfig,
    allowHeaders: ['Content-Type', 'X-Internal-Key', 'Idempotency-Key'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
  })
);

// Global request size cap. The idempotency middleware also enforces 1MB on
// hashed bodies; this is the broader safety net against OOM.
app.use(
  '*',
  bodyLimit({
    maxSize: config.MAX_BODY_BYTES,
    onError: (c) =>
      c.json(
        { error: { code: 'PAYLOAD_TOO_LARGE', message: 'request body exceeds size limit' } },
        413
      ),
  })
);

// Public liveness/info (no auth) at /health, deep checks behind X-Internal-Key
// at /health/deep/*.
app.route('/health', publicHealthRoutes);
app.route('/health/deep', deepHealthRoutes);

// Everything under /v1 requires the X-Internal-Key header.
const v1 = new Hono();
v1.use('*', internalKeyMiddleware);
v1.use('*', idempotencyMiddleware);

v1.route('/ciphertext', ciphertextRoutes);
v1.route('/graph', graphRoutes);
v1.route('/dsl', dslRoutes);
v1.route('/wallet', walletRoutes);
v1.route('/private-tx', transactionRoutes);
v1.route('/decrypt', decryptRoutes);
v1.route('/nek', nekRoutes);
v1.route('/events', eventsRoutes);
v1.route('/authority', authorityRoutes);
v1.route('/fees', feesRoutes);
v1.route('/ownership', ownershipRoutes);
v1.route('/encrypt/decision', decisionRoutes);

app.route('/v1', v1);

app.onError((err, c) => {
  const { status, body } = toApiError(err);
  logger.error({ err, path: c.req.path }, body.error.message);
  return c.json(body, status as 400 | 401 | 403 | 404 | 422 | 500 | 502);
});

app.notFound((c) =>
  c.json({ error: { code: 'NOT_FOUND', message: `route not found: ${c.req.path}` } }, 404)
);

const port = config.PORT;
const server = serve({ fetch: app.fetch, port }, (info) => {
  logger.info(
    { port: info.port, env: config.NODE_ENV, corsAllowed: corsOriginConfig },
    'encrypt-backend listening'
  );
});

let shuttingDown = false;
function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'shutdown initiated — draining in-flight requests');

  const force = setTimeout(() => {
    logger.warn('shutdown drain timed out — forcing exit');
    process.exit(1);
  }, config.SHUTDOWN_TIMEOUT_MS);
  force.unref();

  server.close((err?: Error) => {
    if (err) {
      logger.error({ err }, 'server close error during shutdown');
      process.exit(1);
    } else {
      logger.info('shutdown complete');
      process.exit(0);
    }
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { app };
