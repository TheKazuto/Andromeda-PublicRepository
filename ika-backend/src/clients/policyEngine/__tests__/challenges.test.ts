import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { address, getAddressEncoder, type Address } from '@solana/kit'

import {
  adminChallengeHash,
  adminChallengePreimage,
  humanMessageAllowlistAddDestination,
  humanMessageSpendingUsdAdd,
  humanMessageSpendingUsdAddFeed,
  spendingUsdConfigHash,
  MAX_SPENDING_USD_FEEDS,
  SPENDING_USD_FEED_BYTES,
  OP_ADD_ALLOWLIST,
  OP_ALLOWLIST_ADD_DEST,
  OP_ADD_SPENDING_USD,
  OP_SPENDING_USD_ADD_FEED,
  requestMetadataDigest,
  requestMetadataDigestPreimage,
} from '../challenges.js'
import { KIND_ALLOWLIST, KIND_SPENDING_USD } from '../program.js'

function findFixturesDir(): string {
  let dir = resolve(import.meta.dirname)
  for (let i = 0; i < 10; i += 1) {
    const candidate = join(dir, 'fixtures', 'policy_engine_v3')
    if (existsSync(candidate)) return candidate
    dir = resolve(dir, '..')
  }
  throw new Error('fixtures/policy_engine_v3 not found above test file')
}

interface FixtureFile {
  status: string
  input: Record<string, unknown>
  expected: {
    preimage_hex: string
    preimage_bytes: number
    challenge_hex: string
  }
}

function loadFixture(rel: string): FixtureFile {
  const path = join(findFixturesDir(), rel)
  return JSON.parse(readFileSync(path, 'utf8')) as FixtureFile
}

function hexBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(s.substr(i * 2, 2), 16)
  }
  return out
}

function toHex(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 1) s += b[i]!.toString(16).padStart(2, '0')
  return s
}

function u8(v: unknown): number {
  return Number(v)
}
function u32(v: unknown): number {
  return Number(v)
}
function u64(v: unknown): bigint {
  return BigInt(v as number | string)
}

function u32LE(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v, true)
  return b
}

function u64LE(v: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, v, true)
  return b
}

const addrEnc = getAddressEncoder()

function addrBytes(b58: string): Uint8Array {
  return new Uint8Array(addrEnc.encode(address(b58)))
}

describe('PolicyEngine v3 challenges — cross-language fixtures', () => {
  it('add-rule-allowlist matches fixture', () => {
    const f = loadFixture('challenges/admin/add-rule-allowlist.json')
    expect(f.status).toBe('frozen')
    const inp = f.input as Record<string, string | number>

    const engine = address(inp['engine_b58'] as string) as Address
    const dwallet = address(inp['dwallet_b58'] as string) as Address
    const appliesTo = u8(inp['applies_to'])
    const ruleGeneration = u32(inp['rule_generation'])

    const challengeInput = {
      opTag: OP_ADD_ALLOWLIST,
      humanMessage: new TextEncoder().encode(inp['human_message_utf8'] as string),
      engine,
      dwallet,
      ruleKind: KIND_ALLOWLIST,
      ruleIndex: u8(inp['rule_index']),
      ruleGeneration,
      expectedNonce: u64(inp['expected_nonce']),
      configHash: hexBytes(inp['config_hash_hex'] as string),
      ownerSlot: hexBytes(inp['owner_slot_hex'] as string),
      extras: [new Uint8Array([appliesTo]), u32LE(ruleGeneration)],
    }

    const preimage = adminChallengePreimage(challengeInput)
    expect(toHex(preimage)).toBe(f.expected.preimage_hex)

    const hash = adminChallengeHash(challengeInput)
    expect(toHex(hash)).toBe(f.expected.challenge_hex)
  })

  it('allowlist-add-destination matches fixture', () => {
    const f = loadFixture('challenges/admin/allowlist-add-destination.json')
    expect(f.status).toBe('frozen')
    const inp = f.input as Record<string, string | number>

    const engine = address(inp['engine_b58'] as string) as Address
    const dwallet = address(inp['dwallet_b58'] as string) as Address
    const dest = hexBytes(inp['destination_hex'] as string)
    const ruleGeneration = u32(inp['rule_generation'])

    // Sanity: TS-rendered human message must match the stored one.
    const human = humanMessageAllowlistAddDestination(dest, engine, dwallet)
    const humanStr = new TextDecoder().decode(human)
    expect(humanStr).toBe(inp['human_message_utf8'])

    const challengeInput = {
      opTag: OP_ALLOWLIST_ADD_DEST,
      humanMessage: human,
      engine,
      dwallet,
      ruleKind: KIND_ALLOWLIST,
      ruleIndex: u8(inp['rule_index']),
      ruleGeneration,
      expectedNonce: u64(inp['expected_nonce']),
      configHash: hexBytes(inp['config_hash_hex'] as string),
      ownerSlot: hexBytes(inp['owner_slot_hex'] as string),
      extras: [dest, u32LE(ruleGeneration)],
    }

    const preimage = adminChallengePreimage(challengeInput)
    expect(toHex(preimage)).toBe(f.expected.preimage_hex)

    const hash = adminChallengeHash(challengeInput)
    expect(toHex(hash)).toBe(f.expected.challenge_hex)
  })

  it('request_metadata_digest matches fixture', () => {
    const f = loadFixture('challenges/runtime/request_metadata_digest.json')
    expect(f.status).toBe('frozen')
    const inp = f.input as Record<string, string | number>

    const input = {
      engine: address(inp['engine_b58'] as string) as Address,
      dwallet: address(inp['dwallet_b58'] as string) as Address,
      messageDigest: hexBytes(inp['message_digest_hex'] as string),
      destination: hexBytes(inp['destination_hex'] as string),
      userPubkey: hexBytes(inp['user_pubkey_hex'] as string),
      signatureScheme: u8(inp['signature_scheme']),
      path: u8(inp['path']),
      rulesGeneration: u32(inp['rules_generation']),
      amount: u64(inp['amount']),
      assetIndex: u8(inp['asset_index']),
    }

    const preimage = requestMetadataDigestPreimage(input)
    expect(toHex(preimage)).toBe(f.expected.preimage_hex)

    const digest = requestMetadataDigest(input)
    expect(toHex(digest)).toBe(f.expected.challenge_hex)
  })

  it('add-rule-spending-usd matches fixture', () => {
    const f = loadFixture('challenges/admin/add-rule-spending-usd.json')
    expect(f.status).toBe('frozen')
    const inp = f.input as Record<string, string | number>

    const engine = address(inp['engine_b58'] as string) as Address
    const dwallet = address(inp['dwallet_b58'] as string) as Address
    const appliesTo = u8(inp['applies_to'])
    const freshnessDiv16 = u8(inp['freshness_seconds_div16'])
    const maxConfDiv4 = u8(inp['max_confidence_bps_div4'])
    const maxPerTx = u64(inp['max_per_tx_usd'])
    const maxPerDay = u64(inp['max_per_day_usd'])
    const maxPerWeek = u64(inp['max_per_week_usd'])
    const ruleGeneration = u32(inp['rule_generation'])

    // Sanity: TS-rendered human message + config hash match the fixture.
    const human = humanMessageSpendingUsdAdd(maxPerTx, maxPerDay, maxPerWeek, engine, dwallet)
    expect(new TextDecoder().decode(human)).toBe(inp['human_message_utf8'])
    const emptyFeeds = new Uint8Array(MAX_SPENDING_USD_FEEDS * SPENDING_USD_FEED_BYTES)
    const cfg = spendingUsdConfigHash(
      appliesTo, 0, freshnessDiv16, maxConfDiv4, maxPerTx, maxPerDay, maxPerWeek, emptyFeeds,
    )
    expect(toHex(cfg)).toBe(inp['config_hash_hex'])

    const caps = new Uint8Array(24)
    caps.set(u64LE(maxPerTx), 0)
    caps.set(u64LE(maxPerDay), 8)
    caps.set(u64LE(maxPerWeek), 16)

    const challengeInput = {
      opTag: OP_ADD_SPENDING_USD,
      humanMessage: human,
      engine,
      dwallet,
      ruleKind: KIND_SPENDING_USD,
      ruleIndex: u8(inp['rule_index']),
      ruleGeneration,
      expectedNonce: u64(inp['expected_nonce']),
      configHash: hexBytes(inp['config_hash_hex'] as string),
      ownerSlot: hexBytes(inp['owner_slot_hex'] as string),
      extras: [
        new Uint8Array([appliesTo]),
        new Uint8Array([freshnessDiv16]),
        new Uint8Array([maxConfDiv4]),
        caps,
        u32LE(ruleGeneration),
      ],
    }
    expect(toHex(adminChallengePreimage(challengeInput))).toBe(f.expected.preimage_hex)
    expect(toHex(adminChallengeHash(challengeInput))).toBe(f.expected.challenge_hex)
  })

  it('spending-usd-add-feed matches fixture', () => {
    const f = loadFixture('challenges/admin/spending-usd-add-feed.json')
    expect(f.status).toBe('frozen')
    const inp = f.input as Record<string, string | number>

    const engine = address(inp['engine_b58'] as string) as Address
    const dwallet = address(inp['dwallet_b58'] as string) as Address
    const feedCacheB58 = inp['feed_cache_account_b58'] as string
    const feedCache = address(feedCacheB58) as Address
    const decimals = u8(inp['decimals'])
    const ruleGeneration = u32(inp['rule_generation'])

    const human = humanMessageSpendingUsdAddFeed(feedCache, decimals, engine, dwallet)
    expect(new TextDecoder().decode(human)).toBe(inp['human_message_utf8'])

    const challengeInput = {
      opTag: OP_SPENDING_USD_ADD_FEED,
      humanMessage: human,
      engine,
      dwallet,
      ruleKind: KIND_SPENDING_USD,
      ruleIndex: u8(inp['rule_index']),
      ruleGeneration,
      expectedNonce: u64(inp['expected_nonce']),
      configHash: hexBytes(inp['config_hash_hex'] as string),
      ownerSlot: hexBytes(inp['owner_slot_hex'] as string),
      extras: [addrBytes(feedCacheB58), new Uint8Array([decimals]), u32LE(ruleGeneration)],
    }
    expect(toHex(adminChallengePreimage(challengeInput))).toBe(f.expected.preimage_hex)
    expect(toHex(adminChallengeHash(challengeInput))).toBe(f.expected.challenge_hex)
  })
})
