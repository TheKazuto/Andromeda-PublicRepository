import { describe, it, expect } from 'vitest'
import {
  canonicalIdentityString,
  canonicalSubject,
  deriveWalletAddress,
  deriveWalletAddressFromSubject,
  normalizeEmail,
} from '../derive.js'
import type { VerifiedIdentity } from '../types.js'

const oauth = (provider: 'oauth-google' | 'oauth-apple' | 'oauth-twitter' | 'oauth-github', sub: string): VerifiedIdentity =>
  ({ provider, sub } as VerifiedIdentity)
const email = (e: string): VerifiedIdentity => ({ provider: 'email', email: e } as VerifiedIdentity)
const passkey = (prfHex: string): VerifiedIdentity => ({ provider: 'passkey-prf', prfOutputHex: prfHex } as VerifiedIdentity)

describe('identity/derive — deterministic walletAddress', () => {
  it('is a stable 64-char hex string for a given identity', () => {
    const a = deriveWalletAddress(oauth('oauth-google', 'user-123'))
    const b = deriveWalletAddress(oauth('oauth-google', 'user-123'))
    expect(a).toBe(b)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
  })

  it('cross-client recovery: deriveWalletAddressFromSubject matches deriveWalletAddress for the same identity', () => {
    expect(deriveWalletAddressFromSubject('oauth-google', 'user-123')).toBe(deriveWalletAddress(oauth('oauth-google', 'user-123')))
    expect(deriveWalletAddressFromSubject('oauth-github', 'gh|99')).toBe(deriveWalletAddress(oauth('oauth-github', 'gh|99')))
    expect(deriveWalletAddressFromSubject('email', 'Bob@Example.com')).toBe(deriveWalletAddress(email('  bob@example.com ')))
    expect(deriveWalletAddressFromSubject('passkey-prf', 'AABBCC')).toBe(deriveWalletAddress(passkey('aabbcc')))
  })

  it('different providers with the same subject cannot collide', () => {
    const addrs = new Set([
      deriveWalletAddress(oauth('oauth-google', 'x')),
      deriveWalletAddress(oauth('oauth-apple', 'x')),
      deriveWalletAddress(oauth('oauth-twitter', 'x')),
      deriveWalletAddress(oauth('oauth-github', 'x')),
      deriveWalletAddress(email('x@x.com')),
      deriveWalletAddress(passkey('x')),
    ])
    expect(addrs.size).toBe(6)
  })

  it('email derivation is case-insensitive and whitespace-trimmed', () => {
    expect(deriveWalletAddress(email('Alice@Example.COM'))).toBe(deriveWalletAddress(email('  alice@example.com')))
    expect(normalizeEmail('  Foo@BAR.com ')).toBe('foo@bar.com')
  })

  it('passkey derivation is case-insensitive on the PRF hex', () => {
    expect(deriveWalletAddress(passkey('DEADBEEF'))).toBe(deriveWalletAddress(passkey('deadbeef')))
  })

  it('canonicalIdentityString uses a provider-prefixed form', () => {
    expect(canonicalIdentityString(oauth('oauth-google', 'u'))).toBe('oauth:google:u')
    expect(canonicalIdentityString(email('A@B.com'))).toBe('email:a@b.com')
    expect(canonicalIdentityString(passkey('AB'))).toBe('passkey:ab')
  })

  it('canonicalSubject returns the provider + normalized subject', () => {
    expect(canonicalSubject(oauth('oauth-twitter', 'tw|1'))).toEqual({ provider: 'oauth-twitter', subject: 'tw|1' })
    expect(canonicalSubject(email('A@B.com'))).toEqual({ provider: 'email', subject: 'a@b.com' })
    expect(canonicalSubject(passkey('AB'))).toEqual({ provider: 'passkey-prf', subject: 'ab' })
  })
})
