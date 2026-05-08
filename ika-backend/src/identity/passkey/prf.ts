// Passkey-as-identity — PRF extension helpers.
//
// The WebAuthn PRF extension makes passkeys usable as a stable identity
// factor: given a (credential, salt) pair the authenticator produces a
// deterministic 32-byte HMAC. We seed the salt with
// IKA_IDENTITY_PASSKEY_PRF_SALT and read the result back from
// `clientExtensionResults.prf.results.first`.

import { getIdentityConfig } from '../config.js'

export class PrfNotSupportedError extends Error {
  constructor(message = 'Passkey PRF extension is not supported on this device or browser') {
    super(message)
    this.name = 'PrfNotSupportedError'
  }
}

export function getPrfSaltBytes(): Buffer {
  const hex = getIdentityConfig().passkey.prfSaltHex
  if (!hex) throw new Error('IKA_IDENTITY_PASSKEY_PRF_SALT is not configured')
  return Buffer.from(hex, 'hex')
}

export function extractPrfOutputHex(value: unknown): string {
  if (value === null || value === undefined) {
    throw new PrfNotSupportedError('Client did not return PRF output')
  }
  if (typeof value === 'string') {
    return normalizePrfStringValue(value)
  }
  if (Array.isArray(value)) {
    if (!value.every((v) => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 255)) {
      throw new Error('PRF output array contained non-byte values')
    }
    return Buffer.from(value as number[]).toString('hex')
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value).toString('hex')
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength).toString('hex')
  }
  if (
    typeof value === 'object' &&
    value !== null &&
    'data' in value &&
    Array.isArray((value as { data: unknown }).data)
  ) {
    return extractPrfOutputHex((value as { data: unknown[] }).data)
  }
  throw new Error('Unrecognized PRF output encoding')
}

function normalizePrfStringValue(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length === 0) throw new PrfNotSupportedError('Client returned empty PRF output')
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return trimmed.toLowerCase()
  }
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'base64url').toString('hex')
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'base64').toString('hex')
  }
  throw new Error('Could not decode PRF output string')
}

export function extractPrfFromClientExtensionResults(clientExtensionResults: unknown): string {
  if (!clientExtensionResults || typeof clientExtensionResults !== 'object') {
    throw new PrfNotSupportedError()
  }
  const prf = (clientExtensionResults as { prf?: unknown }).prf
  if (!prf || typeof prf !== 'object') throw new PrfNotSupportedError()
  const results = (prf as { results?: unknown }).results
  if (!results || typeof results !== 'object') throw new PrfNotSupportedError()
  const first = (results as { first?: unknown }).first
  return extractPrfOutputHex(first)
}
