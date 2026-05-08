import type { MiddlewareHandler } from 'hono';
import { config } from '../config.js';
import { Errors } from '../lib/errors.js';

/**
 * Internal-only auth middleware.
 *
 * The encrypt-backend is meant to run on a private network and only be
 * consumed by the API/MCP layer in front of it. This middleware enforces a
 * shared secret header so any leaked address still cannot be used by a third
 * party. It is NOT a per-tenant authentication system — that is handled by
 * the upstream service.
 */
export const internalKeyMiddleware: MiddlewareHandler = async (c, next) => {
  const provided = c.req.header('x-internal-key');
  if (!provided) throw Errors.unauthorized('Missing X-Internal-Key header');
  if (!safeEqual(provided, config.INTERNAL_API_KEY)) {
    throw Errors.unauthorized('Invalid X-Internal-Key');
  }
  await next();
};

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
