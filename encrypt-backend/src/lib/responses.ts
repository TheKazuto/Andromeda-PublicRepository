/**
 * Shared HTTP response helpers.
 *
 * Centralizes the unsignedTx serialization shape used across all `/prepare`
 * routes so we keep the public contract identical and avoid drift.
 */

import type { Address } from '@solana/kit';
import { encodeBase64 } from './validation.js';

export type UnsignedTxResponse = {
  base64: string;
  feePayer: string;
  recentBlockhash: string;
  lastValidBlockHeight: string;
};

export function serializeUnsignedTx(tx: {
  base64: string;
  feePayer: Address | string;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
}): UnsignedTxResponse {
  return {
    base64: tx.base64,
    feePayer: String(tx.feePayer),
    recentBlockhash: tx.recentBlockhash,
    lastValidBlockHeight: tx.lastValidBlockHeight.toString(),
  };
}

/**
 * Normalize the `data` field returned by @solana/kit's fetchEncodedAccount.
 * The runtime shape may be a Uint8Array, a Buffer, or a base64 string depending
 * on encoding hints — collapse them to a base64 string for the JSON response.
 */
export function accountDataToBase64(data: unknown): string {
  if (data instanceof Uint8Array) return encodeBase64(data);
  if (typeof data === 'string') return data;
  if (Array.isArray(data) && typeof data[0] === 'string') return data[0];
  return encodeBase64(new Uint8Array());
}
