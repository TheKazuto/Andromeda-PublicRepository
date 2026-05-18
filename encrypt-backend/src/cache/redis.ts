import { Redis } from '@upstash/redis';
import { config, isCacheEnabled } from '../config.js';
import { logger } from '../lib/logger.js';
import { withTimeout } from '../lib/timeout.js';

/**
 * Optional Upstash Redis cache. If credentials are not set, the cache becomes
 * a no-op so the backend keeps working without Redis (useful for local dev).
 */

let client: Redis | null = null;

if (isCacheEnabled) {
  client = new Redis({
    url: config.UPSTASH_REDIS_REST_URL!,
    token: config.UPSTASH_REDIS_REST_TOKEN!,
  });
  logger.info('Upstash Redis cache enabled');
} else {
  logger.warn('Upstash Redis not configured — cache disabled');
}

export async function cacheGet<T = unknown>(key: string): Promise<T | null> {
  if (!client) return null;
  try {
    return (await withTimeout(client.get<T>(key), config.REDIS_TIMEOUT_MS, 'cache get timed out')) ?? null;
  } catch (err) {
    logger.warn({ err, key }, 'cache get failed');
    return null;
  }
}

export async function cacheSet(key: string, value: unknown, ttlSeconds: number): Promise<void> {
  if (!client) return;
  try {
    await withTimeout(client.set(key, value, { ex: ttlSeconds }), config.REDIS_TIMEOUT_MS, 'cache set timed out');
  } catch (err) {
    logger.warn({ err, key }, 'cache set failed');
  }
}

/**
 * SET key value NX EX ttl — returns true if the key was newly acquired,
 * false if another process already held it. Used by the idempotency
 * middleware to claim the key atomically across replicas before running
 * the mutation. Returns null when Redis is disabled or unreachable so
 * the caller can decide whether to fail-closed (production) or fail-open
 * (dev).
 */
export async function cacheSetNX(
  key: string,
  value: unknown,
  ttlSeconds: number,
): Promise<boolean | null> {
  if (!client) return null;
  try {
    const res = await withTimeout(
      client.set(key, value, { ex: ttlSeconds, nx: true }),
      config.REDIS_TIMEOUT_MS,
      'cache setNX timed out',
    );
    // Upstash returns 'OK' on success, null when NX precluded the write.
    return res === 'OK';
  } catch (err) {
    logger.warn({ err, key }, 'cache setNX failed');
    return null;
  }
}

export async function cacheDel(key: string): Promise<void> {
  if (!client) return;
  try {
    await withTimeout(client.del(key), config.REDIS_TIMEOUT_MS, 'cache del timed out');
  } catch (err) {
    logger.warn({ err, key }, 'cache del failed');
  }
}

export async function cachePing(): Promise<boolean> {
  if (!client) return false;
  try {
    const res = await withTimeout(client.ping(), config.REDIS_TIMEOUT_MS, 'cache ping timed out');
    return res === 'PONG';
  } catch {
    return false;
  }
}

export const cacheKeys = {
  nekCurrent: () => 'encrypt:nek:current',
  ciphertext: (handle: string) => `encrypt:ct:${handle}`,
  graphStatus: (signature: string) => `encrypt:graph:${signature}`,
};
