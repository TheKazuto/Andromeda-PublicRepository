import { describe, it, expect } from 'vitest'
import { adminActionFromInput, decodeBase64, decodeBase64Fixed, decodeMemberSlot } from './dto.js'

const b64 = (n: number, fill = 1): string => Buffer.from(new Uint8Array(n).fill(fill)).toString('base64')

describe('recovery/policy/dto — decoders', () => {
  it('decodeBase64Fixed: enforces exact byte length and base64 validity', () => {
    expect(Array.from(decodeBase64Fixed(b64(32, 5), 32, 'x'))).toEqual(Array.from(new Uint8Array(32).fill(5)))
    expect(() => decodeBase64Fixed(b64(31), 32, 'x')).toThrow('must be 32 bytes (got 31)')
    expect(() => decodeBase64Fixed('!!!notb64!!!', 32, 'x')).toThrow('must be valid base64')
  })

  it('decodeBase64: variable length, base64 validity', () => {
    expect(decodeBase64(b64(10), 'x')).toHaveLength(10)
    expect(() => decodeBase64('@@@', 'x')).toThrow('must be valid base64')
  })

  it('decodeMemberSlot: scheme → identifier length (32 / 20 / 33)', () => {
    expect(decodeMemberSlot({ scheme: 0, identifierBase64: b64(32) }).identifier).toHaveLength(32)
    expect(decodeMemberSlot({ scheme: 1, identifierBase64: b64(20) }).identifier).toHaveLength(20)
    expect(decodeMemberSlot({ scheme: 2, identifierBase64: b64(33) }).identifier).toHaveLength(33)
    expect(decodeMemberSlot({ scheme: 3, identifierBase64: b64(33) }).identifier).toHaveLength(33)
    expect(decodeMemberSlot({ scheme: 0, identifierBase64: b64(32), label: 'hw' }).label).toBe('hw')
  })

  it('decodeMemberSlot: rejects length mismatch and bad base64', () => {
    expect(() => decodeMemberSlot({ scheme: 0, identifierBase64: b64(20) })).toThrow('does not match scheme 0')
    expect(() => decodeMemberSlot({ scheme: 1, identifierBase64: '###' })).toThrow('must be valid base64')
  })

  it('adminActionFromInput: maps each variant and decodes its payloads', () => {
    expect(adminActionFromInput({ type: 'revoke' })).toEqual({ type: 'revoke' })
    expect(adminActionFromInput({ type: 'add_member', member: { scheme: 0, identifierBase64: b64(32, 2) } })).toEqual({
      type: 'add_member',
      member: { scheme: 0, identifier: new Uint8Array(32).fill(2) },
    })
    expect(adminActionFromInput({ type: 'add_destination', destinationBase64: b64(32, 3) })).toEqual({
      type: 'add_destination',
      destination: new Uint8Array(32).fill(3),
    })
    expect(adminActionFromInput({ type: 'set_quorum_threshold_immediate', newThreshold: 3 })).toEqual({
      type: 'set_quorum_threshold_immediate',
      newThreshold: 3,
    })
    expect(adminActionFromInput({ type: 'set_daily_limit_immediate', newSome: true, newLimit: 1000n })).toEqual({
      type: 'set_daily_limit_immediate',
      newSome: true,
      newLimit: 1000n,
    })
    expect(adminActionFromInput({ type: 'set_cooldown_immediate', newCooldownSeconds: 86_400n })).toEqual({
      type: 'set_cooldown_immediate',
      newCooldownSeconds: 86_400n,
    })
    expect(adminActionFromInput({ type: 'set_primary', newPrimary: { scheme: 1, identifierBase64: b64(20, 4) } })).toEqual({
      type: 'set_primary',
      newPrimary: { scheme: 1, identifier: new Uint8Array(20).fill(4) },
    })
  })

  it('adminActionFromInput: bad destination length is rejected', () => {
    expect(() => adminActionFromInput({ type: 'add_destination', destinationBase64: b64(20) })).toThrow('must be 32 bytes (got 20)')
  })
})
