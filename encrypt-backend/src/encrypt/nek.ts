/**
 * NetworkEncryptionKey (NEK) management.
 *
 * The active NEK is registered on-chain by an Encrypt authority via the
 * `register_network_encryption_key` instruction (discriminator 21). Off-chain
 * callers fetch the current public key bytes (32 bytes) and use them as the
 * `network_encryption_public_key` field when calling CreateInput.
 *
 * Resolution order on every request:
 *   1. in-memory override (operator-set; never expires)
 *   2. in-process micro-cache (NEK_INMEM_CACHE_TTL_MS)
 *   3. Redis (Upstash) cache (CACHE_TTL_NEK)
 *   4. live fetch (placeholder until SDK exposes a canonical method)
 *
 * The micro-cache + singleflight pattern eliminates the per-request Redis
 * round-trip on the hot path (createInputCiphertexts is called from every
 * wallet/transfer/check/deposit flow).
 */

import { config } from '../config.js';
import { cacheGet, cacheSet, cacheDel, cacheKeys } from '../cache/redis.js';
import { logger } from '../lib/logger.js';
import { Errors } from '../lib/errors.js';
import { encodeBase64, decodeBase64 } from '../lib/validation.js';

export type NekInfo = {
  publicKey: Uint8Array;     // 32 bytes
  publicKeyBase64: string;   // for HTTP responses
  fetchedAt: string;         // ISO timestamp
  source: 'cache' | 'grpc' | 'override' | 'memory';
};

let inMemoryOverride: { bytes: Uint8Array; base64: string } | null = null;
let nekLocked = false;
let inMemCache: { info: NekInfo; expiresAt: number } | null = null;
let inflight: Promise<NekInfo> | null = null;

const bootNek = config.ENCRYPT_NEK_PUBLIC_KEY_BASE64
  ? decodeBase64(config.ENCRYPT_NEK_PUBLIC_KEY_BASE64)
  : null;

if (bootNek) {
  if (bootNek.length !== 32) {
    throw Errors.nek('ENCRYPT_NEK_PUBLIC_KEY_BASE64 must decode to 32 bytes');
  }
  inMemoryOverride = { bytes: bootNek, base64: encodeBase64(bootNek) };
  if (config.ENCRYPT_NEK_IMMUTABLE) {
    nekLocked = true;
    logger.warn(
      { source: 'env', fingerprint: shortFingerprint(bootNek) },
      'NEK locked at boot via ENCRYPT_NEK_IMMUTABLE=true; /v1/nek/override is now disabled',
    );
  }
}

export class NekImmutableError extends Error {
  constructor() {
    super('NEK is locked (ENCRYPT_NEK_IMMUTABLE=true) — restart the service to rotate.');
    this.name = 'NekImmutableError';
  }
}

/**
 * Allow the upstream service or admin tooling to set the NEK explicitly,
 * bypassing the gRPC fetch. Useful while the on-chain NEK account codec is
 * still in flux. Setting/clearing the override invalidates the in-process
 * cache so the next read reflects the change immediately.
 *
 * When `ENCRYPT_NEK_IMMUTABLE=true`, the first successful set locks the key
 * for the lifetime of the process; subsequent calls throw NekImmutableError.
 * Rotating an active NEK orphans every ciphertext encrypted under the old
 * key, so production must explicitly opt in to mutability.
 *
 * Every call is logged at WARN with a short fingerprint so the operation
 * trail is preserved (full audit + actor identity is the gateway's job).
 */
export function setNekOverride(publicKey: Uint8Array | null): void {
  if (nekLocked) {
    logger.warn({ blocked: true }, 'NEK override rejected — key is locked');
    throw new NekImmutableError();
  }
  const previous = inMemoryOverride
    ? shortFingerprint(inMemoryOverride.bytes)
    : null;

  if (publicKey) {
    inMemoryOverride = { bytes: publicKey, base64: encodeBase64(publicKey) };
    void cacheSet(cacheKeys.nekCurrent(), { pk: inMemoryOverride.base64, ts: new Date().toISOString() }, config.CACHE_TTL_NEK);
  } else {
    inMemoryOverride = null;
    void cacheDel(cacheKeys.nekCurrent());
  }
  inMemCache = null;

  logger.warn(
    {
      action: 'nek.override',
      previousFingerprint: previous,
      nextFingerprint: publicKey ? shortFingerprint(publicKey) : null,
      cleared: publicKey === null,
    },
    'NEK override applied',
  );

  if (config.ENCRYPT_NEK_IMMUTABLE && publicKey) {
    nekLocked = true;
    logger.warn(
      { fingerprint: shortFingerprint(publicKey) },
      'NEK locked after first override (ENCRYPT_NEK_IMMUTABLE=true)',
    );
  }
}

/**
 * shortFingerprint returns the first 8 bytes of the public key as hex. Used
 * in audit logs so operators can correlate NEK changes without exposing the
 * full key (the public key itself is non-secret, but compact correlation IDs
 * are easier to grep).
 */
function shortFingerprint(bytes: Uint8Array): string {
  const view = bytes.subarray(0, 8);
  return Array.from(view, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function getCurrentNek(): Promise<NekInfo> {
  if (inMemoryOverride) {
    return {
      publicKey: inMemoryOverride.bytes,
      publicKeyBase64: inMemoryOverride.base64,
      fetchedAt: new Date().toISOString(),
      source: 'override',
    };
  }

  const now = Date.now();
  if (inMemCache && inMemCache.expiresAt > now) {
    return { ...inMemCache.info, source: 'memory' };
  }

  if (inflight) return inflight;

  inflight = (async () => {
    try {
      const cached = await cacheGet<{ pk: string; ts: string }>(cacheKeys.nekCurrent());
      if (cached) {
        const info: NekInfo = {
          publicKey: decodeBase64(cached.pk),
          publicKeyBase64: cached.pk,
          fetchedAt: cached.ts,
          source: 'cache',
        };
        inMemCache = { info, expiresAt: Date.now() + config.NEK_INMEM_CACHE_TTL_MS };
        return info;
      }

      const fresh = await fetchNekFromNetwork();
      const ts = new Date().toISOString();
      const base64 = encodeBase64(fresh);
      await cacheSet(cacheKeys.nekCurrent(), { pk: base64, ts }, config.CACHE_TTL_NEK);
      const info: NekInfo = {
        publicKey: fresh,
        publicKeyBase64: base64,
        fetchedAt: ts,
        source: 'grpc',
      };
      inMemCache = { info, expiresAt: Date.now() + config.NEK_INMEM_CACHE_TTL_MS };
      return info;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

/**
 * Placeholder NEK fetch. The Encrypt SDK does not expose a stable method for
 * this in pre-alpha — the active key is registered on-chain via discriminator
 * 21 and surfaced via SDK helpers that are still moving. Until that lands we
 * surface a clear error so the operator sets it via override.
 */
async function fetchNekFromNetwork(): Promise<Uint8Array> {
  throw Errors.nek(
    'NEK fetch not implemented — set INTERNAL_NEK_OVERRIDE via /v1/nek/override or wait for SDK helper'
  );
}
