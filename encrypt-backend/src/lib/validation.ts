import { z } from 'zod';

// Common primitive schemas reused across routes
export const Base58String = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,88}$/, 'invalid base58 string');
export const Base64String = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, 'invalid base64 string');
export const HexString = z.string().regex(/^(0x)?[0-9a-fA-F]+$/, 'invalid hex string');
export const PubkeyBase58 = Base58String;
export const NonEmptyString = z.string().min(1);

// Encrypt FHE types — see DSL reference. EUint64 = 4 in the current pre-alpha
// SDK. Plaintext and vector variants use higher discriminants, so accept the
// full u8 range and let the Encrypt executor reject unsupported ids.
export const FheTypeId = z
  .number()
  .int()
  .min(0)
  .max(255, 'fhe_type out of range — see Encrypt DSL reference');

export const CiphertextHandle = Base58String.or(Base64String).or(HexString);

export const Lamports = z.coerce.number().int().nonnegative();

// Helper: parse a base64 string into a Uint8Array (zero-copy view over the
// underlying ArrayBuffer; avoids the per-byte clone that Uint8Array.from does).
export function decodeBase64(input: string): Uint8Array {
  const buf = Buffer.from(input, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function decodeBase64Sized(input: string, size: number, field: string): Uint8Array {
  const bytes = decodeBase64(input);
  if (bytes.length !== size) {
    throw new Error(`${field} must be ${size} bytes`);
  }
  return bytes;
}

// Helper: encode a Uint8Array (or ReadonlyUint8Array) into base64
export function encodeBase64(input: Uint8Array | Readonly<Uint8Array>): string {
  return Buffer.from(input as Uint8Array).toString('base64');
}

// Helper: parse hex string into Uint8Array (zero-copy view).
export function decodeHex(input: string): Uint8Array {
  const clean = input.startsWith('0x') ? input.slice(2) : input;
  const buf = Buffer.from(clean, 'hex');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function encodeHex(input: Uint8Array): string {
  return Buffer.from(input).toString('hex');
}
