import { describe, expect, it } from 'vitest'
import {
  audienceHash,
  deriveAddrSeed,
  deriveOidcNonce,
  issuerHash,
  kidHash,
  OIDC_HASH_LEN,
  OIDC_NONCE_B64_LEN,
  oidcPrimarySlotBytes,
  subjectHash,
  toBase64,
} from '../derive.js'

const GOOGLE_ISS = 'https://accounts.google.com'
const BROKER_AUD = 'andromeda-broker-devnet'
const SUB = '107492837465019283746'

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')

describe('oidc/derive — addr_seed', () => {
  it('is deterministic and 32 bytes', () => {
    const a1 = deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, SUB)
    const a2 = deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, SUB)
    expect(a1.length).toBe(OIDC_HASH_LEN)
    expect(b64(a1)).toBe(b64(a2))
  })

  it('matches the frozen golden vector', () => {
    // Computed from `SHA256("andromeda::oidc::addr::v1" || u16le(len(iss)) ||
    // iss || u16le(len(aud)) || aud || u16le(len(sub)) || sub)` — must equal
    // `oidc_verifier::derive_addr_seed` (same byte layout).
    expect(b64(deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, SUB))).toBe(
      'goJ6f0V0BDnTPQ2q6g7RIa/xBSavXAHijNI118BKPr4=',
    )
  })

  it('changes with sub / aud / iss', () => {
    const base = b64(deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, SUB))
    expect(b64(deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, 'other-sub'))).not.toBe(base)
    expect(b64(deriveAddrSeed(GOOGLE_ISS, 'other-aud', SUB))).not.toBe(base)
    expect(b64(deriveAddrSeed('https://appleid.apple.com', BROKER_AUD, SUB))).not.toBe(base)
  })

  it('length-prefixing makes concatenation unambiguous', () => {
    expect(b64(deriveAddrSeed('ab', 'c', 'd'))).not.toBe(b64(deriveAddrSeed('a', 'bc', 'd')))
    expect(b64(deriveAddrSeed('a', 'b', 'cd'))).not.toBe(b64(deriveAddrSeed('a', 'bc', 'd')))
  })

  it('builds the canonical primary slot [4, addr_seed, 0]', () => {
    const seed = deriveAddrSeed(GOOGLE_ISS, BROKER_AUD, SUB)
    const slot = oidcPrimarySlotBytes(seed)
    expect(slot.length).toBe(34)
    expect(slot[0]).toBe(4)
    expect(b64(slot.slice(1, 33))).toBe(b64(seed))
    expect(slot[33]).toBe(0)
    expect(() => oidcPrimarySlotBytes(new Uint8Array(31))).toThrow()
  })
})

describe('oidc/derive — oidc_nonce', () => {
  it('is deterministic and a 43-char base64url string', () => {
    const ephPk = new Uint8Array(32).fill(7)
    const rand = new Uint8Array(32).fill(9)
    const n1 = deriveOidcNonce(ephPk, 1_770_003_000n, rand)
    const n2 = deriveOidcNonce(ephPk, 1_770_003_000n, rand)
    expect(n1).toBe(n2)
    expect(n1.length).toBe(OIDC_NONCE_B64_LEN)
    expect(n1).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('matches the frozen golden vector', () => {
    expect(deriveOidcNonce(new Uint8Array(32).fill(7), 1_770_003_000n, new Uint8Array(32).fill(9))).toBe(
      'pAqtrYL_Am8SKcwcG9vvIU6k4VoVNsC7V_i2a2cWuaU',
    )
  })

  it('changes with not_after / eph_pk / randomness', () => {
    const ephPk = new Uint8Array(32).fill(7)
    const rand = new Uint8Array(32).fill(9)
    const base = deriveOidcNonce(ephPk, 1_770_003_000n, rand)
    expect(deriveOidcNonce(ephPk, 1_770_003_001n, rand)).not.toBe(base)
    expect(deriveOidcNonce(new Uint8Array(32).fill(8), 1_770_003_000n, rand)).not.toBe(base)
    expect(deriveOidcNonce(ephPk, 1_770_003_000n, new Uint8Array(32).fill(10))).not.toBe(base)
  })

  it('rejects bad-length inputs', () => {
    expect(() => deriveOidcNonce(new Uint8Array(31), 0n, new Uint8Array(32))).toThrow()
    expect(() => deriveOidcNonce(new Uint8Array(32), 0n, new Uint8Array(33))).toThrow()
  })
})

describe('oidc/derive — lookup hashes', () => {
  it('issuer/audience/kid hashes are 32-byte sha256 of the utf8 string', () => {
    expect(issuerHash(GOOGLE_ISS).length).toBe(OIDC_HASH_LEN)
    expect(b64(issuerHash(GOOGLE_ISS))).toBe('iagACmjXWcaL+uq1BW1nNC6XZDURkj5jcC2lipqsjzg=')
    expect(b64(audienceHash(BROKER_AUD))).not.toBe(b64(audienceHash('other')))
    expect(b64(kidHash('k1'))).not.toBe(b64(kidHash('k2')))
  })
})

describe('oidc/derive — subjectHash', () => {
  it('is deterministic per (secret, iss, aud, sub) and changes with the secret', () => {
    const s1 = subjectHash('secret-a', GOOGLE_ISS, BROKER_AUD, SUB)
    const s2 = subjectHash('secret-a', GOOGLE_ISS, BROKER_AUD, SUB)
    const s3 = subjectHash('secret-b', GOOGLE_ISS, BROKER_AUD, SUB)
    expect(s1.length).toBe(OIDC_HASH_LEN)
    expect(b64(s1)).toBe(b64(s2))
    expect(b64(s1)).not.toBe(b64(s3))
  })

  it('the 0x00 separators prevent (iss‖aud) ambiguity', () => {
    const a = subjectHash('k', 'a', 'bc', 'd')
    const b = subjectHash('k', 'ab', 'c', 'd')
    expect(b64(a)).not.toBe(b64(b))
  })
})

describe('oidc/derive — toBase64', () => {
  it('round-trips bytes', () => {
    const bytes = new Uint8Array([0, 1, 254, 255, 42])
    expect(Buffer.from(toBase64(bytes), 'base64')).toEqual(Buffer.from(bytes))
  })
})
