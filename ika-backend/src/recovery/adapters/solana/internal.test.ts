import { describe, it, expect } from 'vitest'
import {
  idLen,
  memberSlotFromCanonical,
  memberSlotToCanonical,
  makeSolanaCtx,
} from './internal.js'
import { SCHEME_ED25519, SCHEME_SECP256K1, SCHEME_SECP256R1, SCHEME_WEBAUTHN } from '../../../clients/rulesPolicy/index.js'

describe('recovery/adapters/solana/internal — pure helpers', () => {
  it('idLen maps schemes to identifier lengths', () => {
    expect(idLen(SCHEME_ED25519)).toBe(32)
    expect(idLen(SCHEME_SECP256K1)).toBe(20)
    expect(idLen(SCHEME_SECP256R1)).toBe(33)
    expect(idLen(SCHEME_WEBAUTHN)).toBe(33)
    expect(() => idLen(99)).toThrow('Unsupported scheme')
  })

  it('memberSlotToCanonical produces a 34-byte [scheme, ...identifier, 0..0] slot', () => {
    const id = new Uint8Array(20).fill(0xab)
    const slot = memberSlotToCanonical({ scheme: SCHEME_SECP256K1, identifier: id })
    expect(slot).toHaveLength(34)
    expect(slot[0]).toBe(SCHEME_SECP256K1)
    expect(Array.from(slot.slice(1, 21))).toEqual(Array.from(id))
    expect(Array.from(slot.slice(21))).toEqual(Array.from(new Uint8Array(13)))
  })

  it('memberSlotToCanonical rejects an identifier whose length does not match the scheme', () => {
    expect(() => memberSlotToCanonical({ scheme: SCHEME_ED25519, identifier: new Uint8Array(20) })).toThrow(
      'does not match scheme',
    )
  })

  it('round-trips a member slot through canonical form (all four schemes)', () => {
    for (const [scheme, len] of [
      [SCHEME_ED25519, 32],
      [SCHEME_SECP256K1, 20],
      [SCHEME_SECP256R1, 33],
      [SCHEME_WEBAUTHN, 33],
    ] as const) {
      const id = new Uint8Array(len).map((_, i) => (i * 7 + scheme) & 0xff)
      const back = memberSlotFromCanonical(memberSlotToCanonical({ scheme, identifier: id, label: 'l' }), 'l')
      expect(back.scheme).toBe(scheme)
      expect(Array.from(back.identifier)).toEqual(Array.from(id))
      expect(back.label).toBe('l')
    }
  })

  it('makeSolanaCtx resolves addresses and lazily validates the coordinator', () => {
    const sysvar = '11111111111111111111111111111111'
    const ctx = makeSolanaCtx({
      programId: sysvar,
      ikaProgramId: sysvar,
      ikaCoordinatorAddress: undefined,
      defaultCooldownSeconds: 604800,
      minCooldownSeconds: 3600,
    })
    expect(ctx.programId).toBe(sysvar)
    expect(ctx.minCooldownSeconds).toBe(3600)
    expect(() => ctx.coordinator()).toThrow('IKA_COORDINATOR_ADDRESS not configured')

    const ctx2 = makeSolanaCtx({
      programId: sysvar,
      ikaProgramId: sysvar,
      ikaCoordinatorAddress: sysvar,
      defaultCooldownSeconds: 604800,
      minCooldownSeconds: 3600,
    })
    expect(ctx2.coordinator()).toBe(sysvar)
  })
})
