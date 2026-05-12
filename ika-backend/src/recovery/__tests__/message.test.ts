import { describe, it, expect } from 'vitest'
import { buildCanonicalMessage, generateNonce, messageHash32 } from '../message.js'

// The canonical message is what every discovery scheme actually signs (after
// each scheme wraps/hashes it per its own convention) — its exact line layout
// is part of the verifier contract, so freeze it here.
describe('recovery/message — canonical discovery message', () => {
  it('has the exact, stable line layout', () => {
    const msg = buildCanonicalMessage({
      appId: 'my-app',
      walletAddress: 'WALLET123',
      scheme: 'ed25519-raw',
      nonce: 'NONCE-abc_1',
      issuedAtIso: '2026-01-01T00:00:00.000Z',
      expiresAtIso: '2026-01-01T00:05:00.000Z',
    })
    expect(msg).toBe(
      [
        'Version: andromeda-ika-recovery-v1',
        'App: my-app',
        'Wallet: WALLET123',
        'Scheme: ed25519-raw',
        'Nonce: NONCE-abc_1',
        'IssuedAt: 2026-01-01T00:00:00.000Z',
        'ExpiresAt: 2026-01-01T00:05:00.000Z',
        'Action: prove ownership for andromeda recovery',
      ].join('\n'),
    )
  })

  it('exposes App: and Nonce: lines parseable by the NEAR/Aptos verifiers', () => {
    const msg = buildCanonicalMessage({
      appId: 'cool app',
      walletAddress: 'w',
      scheme: 'ed25519-near',
      nonce: 'abc_DEF-123',
      issuedAtIso: '2026-01-01T00:00:00.000Z',
      expiresAtIso: '2026-01-01T00:05:00.000Z',
    })
    expect(/^App:\s*(.+)$/m.exec(msg)?.[1]?.trim()).toBe('cool app')
    expect(/^Nonce:\s*([A-Za-z0-9_-]+)$/m.exec(msg)?.[1]).toBe('abc_DEF-123')
  })

  it('generateNonce yields a fresh base64url token each call', () => {
    const a = generateNonce()
    const b = generateNonce()
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(a).not.toBe(b)
  })

  it('messageHash32 is a deterministic 32-byte SHA-256', () => {
    const h1 = messageHash32('hello')
    const h2 = messageHash32('hello')
    expect(h1).toHaveLength(32)
    expect(Buffer.from(h1).equals(Buffer.from(h2))).toBe(true)
    expect(Buffer.from(messageHash32('world')).equals(Buffer.from(h1))).toBe(false)
  })
})
