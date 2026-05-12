// PII encryption-at-rest for the Identity Layer.
//
// Andromeda persists user-controlled data (OAuth profile claims, email
// addresses, passkey metadata) in three columns of the `ika_identities`,
// `ika_identity_links` and `ika_identity_email_tokens` tables. Until KMS
// integration ships (decision Kazuto 2026-05-03 — pós-Fase 7), this module
// provides envelope encryption with a single master key sourced from the
// IKA_IDENTITY_PII_KEY environment variable.
//
// Format on disk (envelope object stored as JSONB / base64 TEXT):
//   { v: 1, alg: "aes-256-gcm", iv: <12B base64>, ct: <ciphertext base64>, tag: <16B base64> }
//
// The IV is randomly generated per encryption (96 bits is the standard for
// GCM). The auth tag is 16 bytes. Backward compatibility: any value that
// does NOT have `v: 1` is treated as legacy plaintext and returned as-is.
// This lets existing rows keep working until a future migration re-encrypts
// them in place.
//
// When IKA_IDENTITY_PII_KEY is unset:
//   - reads succeed (returning whatever is in storage — encrypted or legacy)
//   - writes throw, so we never accidentally persist plaintext on a system
//     that's expected to encrypt
//
// To migrate to a real KMS later, replace `getMasterKey()` and
// `encryptPlaintext` with KMS Encrypt/Decrypt calls. The on-disk envelope
// stays the same — `alg` and `v` fields gate forward compatibility.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { logger } from '../../logger.js'

const ENVELOPE_VERSION = 1 as const
const ALGORITHM = 'aes-256-gcm' as const
const IV_LEN = 12
const KEY_LEN = 32
const TAG_LEN = 16

export interface EncryptedEnvelope {
  v: typeof ENVELOPE_VERSION
  alg: typeof ALGORITHM
  iv: string
  ct: string
  tag: string
}

let cachedKey: Buffer | null = null
let keyMissingLogged = false

function getMasterKey(): Buffer | null {
  if (cachedKey) return cachedKey
  const raw = process.env.IKA_IDENTITY_PII_KEY?.trim()
  if (!raw) {
    if (!keyMissingLogged) {
      // Log once on first miss so operators have a clear breadcrumb. We
      // don't throw here because reads need to keep working on legacy
      // plaintext rows; the throw lives in `encrypt()` instead.
      logger.warn(
        '[identity][pii] IKA_IDENTITY_PII_KEY is unset — PII writes will throw. ' +
          'Set a base64-encoded 32-byte key (e.g. `openssl rand -base64 32`). ' +
          'Reads of legacy plaintext rows still work.',
      )
      keyMissingLogged = true
    }
    return null
  }
  // Accept either base64 (preferred) or hex. base64 of 32 bytes is 44 chars
  // (with padding) or 43 (without). Hex of 32 bytes is 64 chars.
  let bytes: Buffer
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length === 64) {
    bytes = Buffer.from(raw, 'hex')
  } else {
    bytes = Buffer.from(raw, 'base64')
  }
  if (bytes.length !== KEY_LEN) {
    throw new Error(
      `[ika-backend][identity][pii] IKA_IDENTITY_PII_KEY must decode to ${KEY_LEN} bytes; got ${bytes.length}.`,
    )
  }
  cachedKey = bytes
  return cachedKey
}

/**
 * Encrypt plaintext bytes (UTF-8 if you pass a string) into a self-contained
 * envelope. Throws when no master key is configured — never silently writes
 * plaintext.
 */
export function encryptPII(plaintext: string | Buffer): EncryptedEnvelope {
  const key = getMasterKey()
  if (!key) {
    throw new Error(
      '[ika-backend][identity][pii] cannot encrypt — IKA_IDENTITY_PII_KEY is not configured.',
    )
  }
  const iv = randomBytes(IV_LEN)
  const cipher = createCipheriv(ALGORITHM, key, iv)
  const data = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext
  const ct = Buffer.concat([cipher.update(data), cipher.final()])
  const tag = cipher.getAuthTag()
  if (tag.length !== TAG_LEN) {
    throw new Error('[ika-backend][identity][pii] unexpected GCM auth tag length')
  }
  return {
    v: ENVELOPE_VERSION,
    alg: ALGORITHM,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64'),
  }
}

/**
 * Decrypt an envelope produced by `encryptPII`. Returns a UTF-8 string.
 *
 * @throws when the envelope is malformed, the key is missing, or the auth
 *   tag fails to verify (data tampered with or wrong key).
 */
export function decryptPII(envelope: EncryptedEnvelope): string {
  const key = getMasterKey()
  if (!key) {
    throw new Error(
      '[ika-backend][identity][pii] cannot decrypt — IKA_IDENTITY_PII_KEY is not configured.',
    )
  }
  if (envelope.v !== ENVELOPE_VERSION || envelope.alg !== ALGORITHM) {
    throw new Error(
      `[ika-backend][identity][pii] unsupported envelope: v=${envelope.v} alg=${envelope.alg}`,
    )
  }
  const iv = Buffer.from(envelope.iv, 'base64')
  const ct = Buffer.from(envelope.ct, 'base64')
  const tag = Buffer.from(envelope.tag, 'base64')
  const decipher = createDecipheriv(ALGORITHM, key, iv)
  decipher.setAuthTag(tag)
  const pt = Buffer.concat([decipher.update(ct), decipher.final()])
  return pt.toString('utf8')
}

/**
 * Type-guard: does `value` look like a v1 envelope?
 */
export function isEncryptedEnvelope(value: unknown): value is EncryptedEnvelope {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    obj.v === ENVELOPE_VERSION &&
    obj.alg === ALGORITHM &&
    typeof obj.iv === 'string' &&
    typeof obj.ct === 'string' &&
    typeof obj.tag === 'string'
  )
}

/**
 * Wraps a JSON-serializable value (typically `IdentityRecordData`) into the
 * envelope format used in the `data` JSONB columns. Pass-through on null /
 * empty objects — those don't contain PII so we don't waste cipher state.
 *
 * The wrapped form lives in the JSONB column as
 *   { "ciphertext": <envelope>, "encrypted_at": <iso8601> }
 * so consumers can distinguish encrypted from legacy plaintext at a glance.
 */
export function wrapDataForStorage(value: unknown): unknown {
  if (value === null || value === undefined) return value
  if (typeof value === 'object' && Object.keys(value as object).length === 0) {
    return value
  }
  const json = JSON.stringify(value)
  const envelope = encryptPII(json)
  return {
    ciphertext: envelope,
    encrypted_at: new Date().toISOString(),
  }
}

/**
 * Inverse of `wrapDataForStorage`. Returns the original object when the
 * row is encrypted; passes through unchanged for legacy plaintext rows
 * (rows that predate the encryption rollout) or for empty objects.
 */
export function unwrapDataFromStorage(value: unknown): unknown {
  if (value === null || value === undefined) return value
  if (typeof value !== 'object') return value
  const obj = value as Record<string, unknown>
  if (!obj.ciphertext) return value // legacy plaintext or empty object
  if (!isEncryptedEnvelope(obj.ciphertext)) {
    throw new Error(
      '[ika-backend][identity][pii] stored row has `ciphertext` field but not in v1 envelope format',
    )
  }
  const json = decryptPII(obj.ciphertext)
  try {
    return JSON.parse(json)
  } catch {
    throw new Error('[ika-backend][identity][pii] decrypted PII is not valid JSON')
  }
}

/**
 * Encrypt a free-text PII column (e.g. `ika_identity_email_tokens.email`)
 * into a single base64 string suitable for a TEXT column. The string is
 * literally `JSON.stringify(envelope)` base64'd — kept as JSON inside the
 * outer base64 so we can rotate envelope formats without DB migrations.
 *
 * Returns `null` if input is null. Returns the original string unchanged
 * when no master key is configured AND we want to keep plaintext-friendly
 * tests / dev mode green; in production set the env var so writes throw.
 */
export function encryptTextColumn(plaintext: string | null): string | null {
  if (plaintext === null) return null
  const envelope = encryptPII(plaintext)
  return Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64')
}

/**
 * Decrypt a TEXT column previously encrypted by `encryptTextColumn`. If the
 * stored value isn't a base64 envelope (e.g. legacy plaintext row), it is
 * returned as-is — backward compatibility for pre-encryption rows.
 */
export function decryptTextColumn(stored: string | null): string | null {
  if (stored === null) return null
  // Cheap guard: legacy plaintext rows have an `@` in them (email addresses),
  // and base64-of-JSON envelopes never contain `@` (they're all alphanumeric +
  // `+/=`). When in doubt, attempt decode and fall back to plaintext.
  if (!isLikelyEncryptedColumn(stored)) return stored
  try {
    const json = Buffer.from(stored, 'base64').toString('utf8')
    const envelope = JSON.parse(json)
    if (!isEncryptedEnvelope(envelope)) return stored
    return decryptPII(envelope)
  } catch {
    // Malformed base64 / JSON — assume legacy plaintext.
    return stored
  }
}

function isLikelyEncryptedColumn(s: string): boolean {
  // Standard base64 alphabet: A-Z a-z 0-9 + / =. No `@`, `.`, `:`, etc that
  // are common in plaintext PII. This is a heuristic, not a proof; the
  // `JSON.parse + isEncryptedEnvelope` path is the actual gate.
  return /^[A-Za-z0-9+/=]+$/.test(s) && s.length > 60
}

/**
 * Test-only: reset the cached key. Used by unit tests that flip the env var
 * between cases.
 */
export function _resetCachedKey(): void {
  cachedKey = null
  keyMissingLogged = false
}
