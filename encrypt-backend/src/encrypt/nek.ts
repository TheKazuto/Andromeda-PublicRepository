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
 *   4. on-chain fetch (getProgramAccounts over the NetworkEncryptionKey account)
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
import { rpc } from '../solana/connection.js';
import { ENCRYPT_PROGRAM_ID } from '../solana/programIds.js';
import { withSolanaRpc } from '../solana/rpcwrap.js';

// NetworkEncryptionKey account layout (Encrypt program account kind 7).
// Source: Encrypt account reference (docs.encrypt.xyz/reference/accounts).
//   offset 0  discriminator (1) = 7
//   offset 1  version       (1)
//   offset 2  network_encryption_public_key (32)
//   offset 34 active        (1)  — 1 = active
//   offset 35 bump          (1)
// Total 36 bytes.
const NEK_ACCOUNT_DISCRIMINATOR = 7;
const NEK_ACCOUNT_ACTIVE = 1;
const NEK_ACCOUNT_SIZE = 36;
const NEK_PUBKEY_OFFSET = 2;
const NEK_ACTIVE_OFFSET = 34;

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
 * Fetch the active NEK on-chain. The Encrypt SDK does not expose a typed helper
 * in pre-alpha, and the NetworkEncryptionKey account is a PDA seeded by the key
 * bytes themselves (`["network_encryption_key", key_bytes]`) — so its address
 * can't be derived without already knowing the key, and EncryptConfig holds no
 * pointer to "the active NEK". The only on-chain path is a getProgramAccounts
 * scan filtered to account kind 7 (NetworkEncryptionKey) with `active = 1`.
 *
 * This is a heavy RPC call, so it only runs as the last-resort source (4): the
 * override (env or /v1/nek/override) and the Redis/in-mem caches all short-
 * circuit it. We require exactly one active key — zero or many is ambiguous and
 * we refuse to guess (the wrong NEK orphans every ciphertext encrypted under it).
 */
async function fetchNekFromNetwork(): Promise<Uint8Array> {
  const accounts = await withSolanaRpc('get_network_encryption_key', () =>
    rpc
      .getProgramAccounts(ENCRYPT_PROGRAM_ID, {
        encoding: 'base64',
        filters: [
          { dataSize: BigInt(NEK_ACCOUNT_SIZE) },
          {
            memcmp: {
              offset: 0n,
              bytes: encodeBase64(Uint8Array.from([NEK_ACCOUNT_DISCRIMINATOR])) as never,
              encoding: 'base64',
            },
          },
          {
            memcmp: {
              offset: BigInt(NEK_ACTIVE_OFFSET),
              bytes: encodeBase64(Uint8Array.from([NEK_ACCOUNT_ACTIVE])) as never,
              encoding: 'base64',
            },
          },
        ],
      })
      .send({ abortSignal: AbortSignal.timeout(config.SOLANA_RPC_TIMEOUT_MS) }),
  );

  // Decode + re-validate each candidate; the memcmp filters already narrow
  // server-side, but we never trust the wire for a key this load-bearing.
  const keys: Uint8Array[] = [];
  for (const entry of accounts) {
    const data = entry.account.data;
    const b64 = Array.isArray(data) ? data[0] : undefined;
    if (typeof b64 !== 'string') continue;
    const bytes = decodeBase64(b64);
    if (
      bytes.length !== NEK_ACCOUNT_SIZE ||
      bytes[0] !== NEK_ACCOUNT_DISCRIMINATOR ||
      bytes[NEK_ACTIVE_OFFSET] !== NEK_ACCOUNT_ACTIVE
    ) {
      continue;
    }
    keys.push(bytes.slice(NEK_PUBKEY_OFFSET, NEK_PUBKEY_OFFSET + 32));
  }

  if (keys.length === 0) {
    throw Errors.nek(
      'no active NetworkEncryptionKey found on-chain — set INTERNAL_NEK_OVERRIDE via /v1/nek/override',
    );
  }
  if (keys.length > 1) {
    throw Errors.nek(
      `found ${keys.length} active NetworkEncryptionKeys on-chain — set INTERNAL_NEK_OVERRIDE to disambiguate`,
    );
  }
  return keys[0]!;
}
