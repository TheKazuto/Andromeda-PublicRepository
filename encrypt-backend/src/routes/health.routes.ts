import { Hono } from 'hono';
import { rpc } from '../solana/connection.js';
import { pingEncryptGrpc } from '../encrypt/client.js';
import { cachePing } from '../cache/redis.js';
import { config, isCacheEnabled } from '../config.js';
import { internalKeyMiddleware } from '../auth/internalKey.js';

/**
 * Public liveness/info endpoints (no auth) — meant for platform probes.
 * They MUST NOT touch external dependencies, so a misconfigured probe cannot
 * be amplified into a DoS against gRPC / Solana RPC / Redis.
 */
export const publicHealthRoutes = new Hono();

publicHealthRoutes.get('/', (c) => c.json({ status: 'ok', service: 'encrypt-backend' }));

publicHealthRoutes.get('/info', (c) =>
  c.json({
    service: 'encrypt-backend',
    version: '0.1.0',
    network: 'solana-devnet',
    encryptGrpcUrl: config.ENCRYPT_GRPC_URL,
    encryptProgramId: config.ENCRYPT_PROGRAM_ID,
    cacheEnabled: isCacheEnabled,
  })
);

/**
 * Deep health endpoints (auth-required) — they touch external systems and
 * can incur cost, so they sit behind the same X-Internal-Key as /v1/*.
 *
 * Mounted at /health/deep/* so platform probes still hit /health (public).
 */
export const deepHealthRoutes = new Hono();
deepHealthRoutes.use('*', internalKeyMiddleware);

deepHealthRoutes.get('/grpc', async (c) => {
  const ok = await pingEncryptGrpc();
  return c.json({ ok, url: config.ENCRYPT_GRPC_URL });
});

deepHealthRoutes.get('/solana', async (c) => {
  try {
    const slot = await rpc.getSlot().send();
    return c.json({ ok: true, slot: Number(slot), url: config.SOLANA_RPC_URL });
  } catch (err) {
    return c.json({ ok: false, error: String(err) }, 502);
  }
});

deepHealthRoutes.get('/cache', async (c) => {
  if (!isCacheEnabled) return c.json({ enabled: false });
  const ok = await cachePing();
  return c.json({ enabled: true, ok });
});
