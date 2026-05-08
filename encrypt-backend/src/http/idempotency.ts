/**
 * Defensive Idempotency-Key middleware for encrypt-backend (Hono).
 *
 * The gateway is the primary enforcement point — see
 * `gateway/internal/idempotency/idempotency.go`. Encrypt-backend has no
 * Postgres but does have an optional Upstash Redis cache; we use it when
 * available, and fall through to passthrough otherwise.
 */

import type { Context, MiddlewareHandler } from 'hono';
import { createHash } from 'node:crypto';
import { cacheGet, cacheSet } from '../cache/redis.js';
import { logger } from '../lib/logger.js';
import { config } from '../config.js';

const HEADER = 'idempotency-key';
const REPLAY_HEADER = 'Idempotent-Replay';
const TTL_SECONDS = 24 * 60 * 60;
const SCOPE = 'encrypt';

interface CachedEntry {
  status: number;
  body: string;
  contentType: string;
  requestHash: string;
}

function shouldApply(method: string): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase());
}

function hashBody(buf: Uint8Array): string {
  if (buf.length === 0) return '';
  return createHash('sha256').update(buf).digest('hex');
}

export const idempotencyMiddleware: MiddlewareHandler = async (c: Context, next) => {
  if (!shouldApply(c.req.method)) {
    return next();
  }
  const headerValue = c.req.header(HEADER);
  const idemKey = headerValue ? headerValue.trim() : '';
  if (!idemKey) {
    return next();
  }
  if (idemKey.length < 8 || idemKey.length > 200) {
    return c.json(
      { error: { code: 'invalid_idempotency_key', message: 'Idempotency-Key must be 8-200 chars' } },
      400,
    );
  }

  const apiKeyId = createHash('sha256')
    .update(c.req.header('x-internal-key') ?? 'anon')
    .digest('hex')
    .slice(0, 24);
  const methodPath = `${c.req.method.toUpperCase()} ${new URL(c.req.url).pathname}`;
  const cacheKey = `idem:${SCOPE}:${apiKeyId}:${methodPath}:${idemKey}`;

  let bodyBuf: Uint8Array;
  try {
    bodyBuf = new Uint8Array(await c.req.raw.clone().arrayBuffer());
  } catch {
    bodyBuf = new Uint8Array(0);
  }
  if (bodyBuf.byteLength > config.MAX_BODY_BYTES) {
    return c.json(
      { error: { code: 'body_too_large', message: 'request body exceeds idempotency hash limit' } },
      400,
    );
  }
  const requestHash = hashBody(bodyBuf);

  const cached = await cacheGet<CachedEntry>(cacheKey);
  if (cached) {
    if (cached.requestHash !== requestHash) {
      return c.json(
        {
          error: {
            code: 'idempotency_collision',
            message: 'Idempotency-Key reused with a different request body',
          },
        },
        422,
      );
    }
    c.header(REPLAY_HEADER, 'true');
    c.header('content-type', cached.contentType || 'application/json');
    return c.body(cached.body, cached.status as 200 | 201 | 202 | 400 | 404 | 422);
  }

  await next();

  const status = c.res.status;
  if (status >= 200 && status < 500) {
    try {
      const cloned = c.res.clone();
      const body = await cloned.text();
      const contentType = cloned.headers.get('content-type') ?? 'application/json';
      const entry: CachedEntry = { status, body, contentType, requestHash };
      await cacheSet(cacheKey, entry, TTL_SECONDS);
    } catch (err) {
      logger.warn({ err, cacheKey }, 'idempotency persist failed');
    }
  }
};
