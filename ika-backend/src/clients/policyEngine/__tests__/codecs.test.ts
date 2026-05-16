import { describe, expect, it } from 'vitest'
import { decodeAllowlistRule, decodePolicyEngine } from '../codecs.js'
import { KIND_ALLOWLIST, MEMBER_SLOT_LEN, APPLIES_NORMAL } from '../program.js'

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v, true)
  return b
}

function u64le(v: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, v, true)
  return b
}

describe('PolicyEngine v3 codecs (F2.7 TS mirror)', () => {
  it('decodes a synthesised PolicyEngine PDA round-trip', () => {
    const buf = new Uint8Array(1698)
    buf[0] = 1 // disc
    buf[1] = 1 // version
    // dwallet at 2..34
    for (let i = 0; i < 32; i += 1) buf[2 + i] = i + 1
    // init_authority_slot at 34..68
    buf[34] = 0
    for (let i = 1; i < MEMBER_SLOT_LEN; i += 1) buf[34 + i] = 0x10 + i
    // owner_slot at 68..102
    buf[68] = 0
    for (let i = 1; i < MEMBER_SLOT_LEN; i += 1) buf[68 + i] = 0x20 + i
    buf.set(u64le(7n), 102) // next_admin_nonce
    buf[142] = 0 // paused
    buf[143] = 1 // rules_count
    buf.set(u32le(2), 144) // rules_generation
    // RuleEntry[0] at 154..250
    const off = 154
    buf[off] = KIND_ALLOWLIST
    buf[off + 1] = 254 // bump
    buf[off + 2] = 1
    buf[off + 3] = 1 // enabled
    buf.set(u32le(1), off + 4) // generation
    for (let i = 0; i < 32; i += 1) buf[off + 8 + i] = 0xa0 + i // rule_pda
    for (let i = 0; i < 32; i += 1) buf[off + 40 + i] = 0xc0 + i // config_hash

    const state = decodePolicyEngine(buf)
    expect(state.version).toBe(1)
    expect(state.rulesCount).toBe(1)
    expect(state.rulesGeneration).toBe(2)
    expect(state.nextAdminNonce).toBe(7n)
    expect(state.rules[0]!.kind).toBe(KIND_ALLOWLIST)
    expect(state.rules[0]!.enabled).toBe(true)
    expect(state.rules[0]!.generation).toBe(1)
    expect(state.rules[0]!.bump).toBe(254)
    // Slot 1..15 must decode as empty.
    for (let i = 1; i < 16; i += 1) {
      expect(state.rules[i]!.kind).toBe(0)
    }
  })

  it('rejects PolicyEngine with wrong discriminator', () => {
    const buf = new Uint8Array(1698)
    buf[0] = 99
    expect(() => decodePolicyEngine(buf)).toThrow(/discriminator/)
  })

  it('decodes AllowlistRule with 2 destinations', () => {
    const buf = new Uint8Array(1 + 96 + 8 + 1024)
    buf[0] = 2 // disc
    buf[1] = KIND_ALLOWLIST
    buf[2] = 0
    buf[3] = 1 // enabled
    buf.set(u32le(3), 5) // generation
    buf.set(u32le(1), 9) // config_version
    for (let i = 0; i < 32; i += 1) buf[17 + i] = 0x42 // engine
    buf.set(u64le(5n), 49) // next_admin_nonce
    for (let i = 0; i < 32; i += 1) buf[57 + i] = 0xcc // config_hash
    buf[97] = APPLIES_NORMAL
    buf[98] = 2
    for (let i = 0; i < 32; i += 1) buf[105 + i] = 0xd0 // dest0
    for (let i = 0; i < 32; i += 1) buf[137 + i] = 0xd1 // dest1

    const state = decodeAllowlistRule(buf)
    expect(state.kind).toBe(KIND_ALLOWLIST)
    expect(state.enabled).toBe(true)
    expect(state.generation).toBe(3)
    expect(state.nextAdminNonce).toBe(5n)
    expect(state.appliesTo).toBe(APPLIES_NORMAL)
    expect(state.destinationsCount).toBe(2)
    expect(state.destinations).toHaveLength(2)
    expect(state.destinations[0]![0]).toBe(0xd0)
    expect(state.destinations[1]![0]).toBe(0xd1)
  })
})
