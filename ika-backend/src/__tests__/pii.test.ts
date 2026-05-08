// Tests for the Identity Layer PII encryption envelope.

import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import {
  _resetCachedKey,
  decryptPII,
  decryptTextColumn,
  encryptPII,
  encryptTextColumn,
  isEncryptedEnvelope,
  unwrapDataFromStorage,
  wrapDataForStorage,
} from '../identity/crypto/pii.js'

const TEST_KEY = 'JeBA4ehpPi8gG87/aDx6PdHl9CkftSm2gtRotLg+OCw=' // 32 bytes b64

describe('identity PII envelope', () => {
  let prevKey: string | undefined

  beforeEach(() => {
    prevKey = process.env.IKA_IDENTITY_PII_KEY
    process.env.IKA_IDENTITY_PII_KEY = TEST_KEY
    _resetCachedKey()
  })

  afterEach(() => {
    if (prevKey === undefined) {
      delete process.env.IKA_IDENTITY_PII_KEY
    } else {
      process.env.IKA_IDENTITY_PII_KEY = prevKey
    }
    _resetCachedKey()
  })

  test('round-trips a string through encryptPII / decryptPII', () => {
    const envelope = encryptPII('alice@example.com')
    expect(envelope.v).toBe(1)
    expect(envelope.alg).toBe('aes-256-gcm')
    expect(decryptPII(envelope)).toBe('alice@example.com')
  })

  test('produces fresh IV per call (no IV reuse)', () => {
    const a = encryptPII('same plaintext')
    const b = encryptPII('same plaintext')
    expect(a.iv).not.toBe(b.iv)
    expect(a.ct).not.toBe(b.ct)
  })

  test('rejects tampered ciphertext', () => {
    const envelope = encryptPII('treasure-clue')
    const tampered = { ...envelope, ct: Buffer.from('AAAA', 'base64').toString('base64') }
    expect(() => decryptPII(tampered)).toThrow()
  })

  test('rejects mismatched auth tag', () => {
    const envelope = encryptPII('treasure-clue')
    const tampered = { ...envelope, tag: Buffer.alloc(16).toString('base64') }
    expect(() => decryptPII(tampered)).toThrow()
  })

  test('isEncryptedEnvelope correctly identifies v1 envelopes', () => {
    const envelope = encryptPII('hi')
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    expect(isEncryptedEnvelope({})).toBe(false)
    expect(isEncryptedEnvelope(null)).toBe(false)
    expect(isEncryptedEnvelope({ v: 1, alg: 'aes-256-gcm' })).toBe(false) // missing fields
  })

  test('wrapDataForStorage round-trips a JSONB-shaped object', () => {
    const data = { display_name: 'Alice', preferred_locale: 'en-US' }
    const wrapped = wrapDataForStorage(data) as Record<string, unknown>
    expect(wrapped.ciphertext).toBeDefined()
    expect(wrapped.encrypted_at).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(unwrapDataFromStorage(wrapped)).toEqual(data)
  })

  test('wrapDataForStorage passes through empty objects (no PII)', () => {
    expect(wrapDataForStorage({})).toEqual({})
    expect(unwrapDataFromStorage({})).toEqual({})
  })

  test('unwrapDataFromStorage returns legacy plaintext rows unchanged', () => {
    const legacy = { display_name: 'Bob' } // pre-encryption, raw object
    expect(unwrapDataFromStorage(legacy)).toEqual(legacy)
  })

  test('encryptTextColumn / decryptTextColumn round-trip', () => {
    const enc = encryptTextColumn('alice@example.com')
    expect(enc).not.toBe('alice@example.com')
    expect(decryptTextColumn(enc)).toBe('alice@example.com')
  })

  test('decryptTextColumn passes through legacy plaintext (contains @)', () => {
    expect(decryptTextColumn('legacy@example.com')).toBe('legacy@example.com')
  })

  test('decryptTextColumn passes through null', () => {
    expect(decryptTextColumn(null)).toBe(null)
  })

  test('encrypt throws when key is unset', () => {
    delete process.env.IKA_IDENTITY_PII_KEY
    _resetCachedKey()
    expect(() => encryptPII('x')).toThrow(/IKA_IDENTITY_PII_KEY/)
  })

  test('rejects key that does not decode to 32 bytes', () => {
    process.env.IKA_IDENTITY_PII_KEY = 'aGVsbG8=' // "hello", 5 bytes
    _resetCachedKey()
    expect(() => encryptPII('x')).toThrow(/32 bytes/)
  })

  test('accepts hex-encoded 32-byte key', () => {
    process.env.IKA_IDENTITY_PII_KEY = '00'.repeat(32)
    _resetCachedKey()
    const env = encryptPII('hello world')
    expect(decryptPII(env)).toBe('hello world')
  })
})
