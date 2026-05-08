/**
 * Helpers to compute the `authorized` field passed to CreateInput.
 *
 * Per Encrypt docs the `authorized` value identifies who may use the produced
 * ciphertexts. Two common patterns:
 *   - program-scoped: bytes of a program PDA / program address
 *   - user-scoped: bytes of the user's pubkey
 *
 * We expose a thin helper that takes either a base58 Solana address or raw
 * bytes and returns a normalized 32-byte Uint8Array.
 */

import { address as toAddress, getAddressCodec } from '@solana/kit';
import { Errors } from '../lib/errors.js';

const addressCodec = getAddressCodec();

export function authorizedFromAddress(addr: string): Uint8Array {
  try {
    return new Uint8Array(addressCodec.encode(toAddress(addr)));
  } catch (err) {
    throw Errors.badRequest('invalid Solana address for authorized field', err);
  }
}

export function authorizedFromBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) {
    throw Errors.badRequest('authorized bytes must be 32 long');
  }
  return bytes;
}
