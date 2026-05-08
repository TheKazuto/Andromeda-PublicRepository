/**
 * High-level ReadCiphertext orchestrator with optional caching.
 *
 * The gRPC ReadCiphertext call requires a BCS-serialized ReadCiphertextMessage
 * + Ed25519 signature + signer pubkey. The full BCS layout lives in the
 * upstream `proto` and `chains/solana/clients/typescript` packages. To keep
 * this backend stateless and SDK-shape-agnostic, we accept the already-built
 * message + signature + signer from the caller (typically the upstream API
 * layer that holds user signing context).
 *
 * For convenience we also expose a `cacheKey` parameter so repeated reads of
 * the same ciphertext by the same signer hit Redis instead of re-issuing
 * gRPC calls.
 */

import { callReadCiphertext } from './client.js';
import { cacheGet, cacheSet, cacheKeys } from '../cache/redis.js';
import { config } from '../config.js';
import { encodeBase64, decodeBase64 } from '../lib/validation.js';

export type ReadCiphertextInput = {
  message: Uint8Array;
  signature: Uint8Array;
  signer: Uint8Array;
  /** Optional explicit cache key. If omitted, no caching is performed. */
  cacheKey?: string;
};

export type ReadCiphertextOutput = {
  value: string;       // base64
  fheType: number;
  digest: string;      // base64
  cached: boolean;
};

export async function readCiphertext(input: ReadCiphertextInput): Promise<ReadCiphertextOutput> {
  if (input.cacheKey) {
    const cached = await cacheGet<{ value: string; fheType: number; digest: string }>(
      cacheKeys.ciphertext(input.cacheKey)
    );
    if (cached) {
      return { ...cached, cached: true };
    }
  }

  const res = await callReadCiphertext({
    message: input.message,
    signature: input.signature,
    signer: input.signer,
  });

  const out: Omit<ReadCiphertextOutput, 'cached'> = {
    value: encodeBase64(res.value),
    fheType: res.fheType,
    digest: encodeBase64(res.digest),
  };

  if (input.cacheKey) {
    await cacheSet(cacheKeys.ciphertext(input.cacheKey), out, config.CACHE_TTL_CIPHERTEXT);
  }

  return { ...out, cached: false };
}

export { decodeBase64 };
