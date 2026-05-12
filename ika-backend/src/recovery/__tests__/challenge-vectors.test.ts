import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as C from '../challenge.js'

// The 14 domain-separated recovery challenges are mirrored byte-for-byte by
// contracts/auth/src/challenge.rs. A 1-byte drift means every recovery
// signature fails on-chain (or — worse — verifies when it shouldn't). This
// suite recomputes each challenge from frozen inputs and asserts it still
// matches challenge_vectors.json; regenerate that file (scripts/gen-challenge-
// vectors.ts) ONLY on an intentional wire-format change, and update the Rust
// mirror in the same commit.

interface VectorFile {
  vectors: Record<string, { inputs: Record<string, unknown>; expectedChallengeHex: string }>
}

const __dirname = dirname(fileURLToPath(import.meta.url))

const vectorFile = JSON.parse(
  readFileSync(join(__dirname, 'challenge_vectors.json'), 'utf8'),
) as VectorFile

const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex')
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'))
const I = vectorFile.vectors
const inp = (name: string): Record<string, unknown> => I[name]!.inputs
const u8 = (name: string, key: string): Uint8Array => unhex(inp(name)[key] as string)
const big = (name: string, key: string): bigint => BigInt(inp(name)[key] as string)
const num = (name: string, key: string): number => inp(name)[key] as number
const bool = (name: string, key: string): boolean => inp(name)[key] as boolean

// (name, recompute) — recompute reads the same inputs the generator used.
const cases: Array<[string, () => Uint8Array]> = [
  ['rules_policy_init', () =>
    C.rulesPolicyInitChallenge({
      dwallet: u8('rules_policy_init', 'dwallet'),
      initAuthoritySlot: u8('rules_policy_init', 'initAuthoritySlot'),
      primarySlot: u8('rules_policy_init', 'primarySlot'),
      quorumThreshold: num('rules_policy_init', 'quorumThreshold'),
      dailyLimitSome: bool('rules_policy_init', 'dailyLimitSome'),
      dailyLimit: big('rules_policy_init', 'dailyLimit'),
      cooldownSeconds: big('rules_policy_init', 'cooldownSeconds'),
      allowedDestinationsSome: bool('rules_policy_init', 'allowedDestinationsSome'),
    })],
  ['init_authority_hash_from_slot', () => C.initAuthorityHashFromSlot(u8('init_authority_hash_from_slot', 'slot'))],
  ['primary_recover', () =>
    C.primaryRecoverChallenge({
      dwallet: u8('primary_recover', 'dwallet'),
      messageDigest: u8('primary_recover', 'messageDigest'),
      metadataDigest: u8('primary_recover', 'metadataDigest'),
      nonce: big('primary_recover', 'nonce'),
      primarySlot: u8('primary_recover', 'primarySlot'),
    })],
  ['quorum_session_open', () =>
    C.quorumSessionOpenChallenge({
      dwallet: u8('quorum_session_open', 'dwallet'),
      messageDigest: u8('quorum_session_open', 'messageDigest'),
      metadataDigest: u8('quorum_session_open', 'metadataDigest'),
      amount: big('quorum_session_open', 'amount'),
      destination: u8('quorum_session_open', 'destination'),
      expiresAt: big('quorum_session_open', 'expiresAt'),
      sessionNonce: big('quorum_session_open', 'sessionNonce'),
      primarySlot: u8('quorum_session_open', 'primarySlot'),
    })],
  ['quorum_contribute', () =>
    C.quorumContributeChallenge({ session: u8('quorum_contribute', 'session'), memberSlot: u8('quorum_contribute', 'memberSlot') })],
  ['admin_add_member', () =>
    C.adminAddMemberChallenge({ dwallet: u8('admin_add_member', 'dwallet'), newMemberSlot: u8('admin_add_member', 'newMemberSlot'), nonce: big('admin_add_member', 'nonce'), primarySlot: u8('admin_add_member', 'primarySlot') })],
  ['admin_remove_member', () =>
    C.adminRemoveMemberChallenge({ dwallet: u8('admin_remove_member', 'dwallet'), memberSlotToRemove: u8('admin_remove_member', 'memberSlotToRemove'), nonce: big('admin_remove_member', 'nonce'), primarySlot: u8('admin_remove_member', 'primarySlot') })],
  ['admin_add_destination', () =>
    C.adminAddDestinationChallenge({ dwallet: u8('admin_add_destination', 'dwallet'), destination: u8('admin_add_destination', 'destination'), nonce: big('admin_add_destination', 'nonce'), primarySlot: u8('admin_add_destination', 'primarySlot') })],
  ['admin_remove_destination', () =>
    C.adminRemoveDestinationChallenge({ dwallet: u8('admin_remove_destination', 'dwallet'), destination: u8('admin_remove_destination', 'destination'), nonce: big('admin_remove_destination', 'nonce'), primarySlot: u8('admin_remove_destination', 'primarySlot') })],
  ['admin_revoke', () => C.adminRevokeChallenge({ dwallet: u8('admin_revoke', 'dwallet'), nonce: big('admin_revoke', 'nonce'), primarySlot: u8('admin_revoke', 'primarySlot') })],
  ['admin_set_primary', () =>
    C.adminSetPrimaryChallenge({ dwallet: u8('admin_set_primary', 'dwallet'), newPrimarySlot: u8('admin_set_primary', 'newPrimarySlot'), nonce: big('admin_set_primary', 'nonce'), currentPrimarySlot: u8('admin_set_primary', 'currentPrimarySlot') })],
  ['admin_set_quorum_threshold_immediate', () =>
    C.adminSetQuorumThresholdImmediateChallenge({ dwallet: u8('admin_set_quorum_threshold_immediate', 'dwallet'), newThreshold: num('admin_set_quorum_threshold_immediate', 'newThreshold'), nonce: big('admin_set_quorum_threshold_immediate', 'nonce'), primarySlot: u8('admin_set_quorum_threshold_immediate', 'primarySlot') })],
  ['admin_set_daily_limit_immediate', () =>
    C.adminSetDailyLimitImmediateChallenge({ dwallet: u8('admin_set_daily_limit_immediate', 'dwallet'), newSome: bool('admin_set_daily_limit_immediate', 'newSome'), newLimit: big('admin_set_daily_limit_immediate', 'newLimit'), nonce: big('admin_set_daily_limit_immediate', 'nonce'), primarySlot: u8('admin_set_daily_limit_immediate', 'primarySlot') })],
  ['admin_set_cooldown_immediate', () =>
    C.adminSetCooldownImmediateChallenge({ dwallet: u8('admin_set_cooldown_immediate', 'dwallet'), newCooldownSeconds: big('admin_set_cooldown_immediate', 'newCooldownSeconds'), nonce: big('admin_set_cooldown_immediate', 'nonce'), primarySlot: u8('admin_set_cooldown_immediate', 'primarySlot') })],
  ['admin_propose_quorum_threshold', () =>
    C.adminProposeQuorumThresholdChallenge({ dwallet: u8('admin_propose_quorum_threshold', 'dwallet'), newThreshold: num('admin_propose_quorum_threshold', 'newThreshold'), nonce: big('admin_propose_quorum_threshold', 'nonce'), primarySlot: u8('admin_propose_quorum_threshold', 'primarySlot') })],
  ['admin_propose_daily_limit', () =>
    C.adminProposeDailyLimitChallenge({ dwallet: u8('admin_propose_daily_limit', 'dwallet'), newSome: bool('admin_propose_daily_limit', 'newSome'), newLimit: big('admin_propose_daily_limit', 'newLimit'), nonce: big('admin_propose_daily_limit', 'nonce'), primarySlot: u8('admin_propose_daily_limit', 'primarySlot') })],
  ['admin_propose_cooldown', () =>
    C.adminProposeCooldownChallenge({ dwallet: u8('admin_propose_cooldown', 'dwallet'), newCooldownSeconds: big('admin_propose_cooldown', 'newCooldownSeconds'), nonce: big('admin_propose_cooldown', 'nonce'), primarySlot: u8('admin_propose_cooldown', 'primarySlot') })],
]

describe('recovery/challenge — frozen golden vectors (must match contracts/auth/src/challenge.rs)', () => {
  it('the vector file covers every challenge function', () => {
    expect(cases.map(([n]) => n).sort()).toEqual(Object.keys(I).sort())
  })

  for (const [name, recompute] of cases) {
    it(`${name} still hashes to the frozen value`, () => {
      expect(hex(recompute())).toBe(I[name]!.expectedChallengeHex)
    })
  }

  it('every challenge is a distinct 32-byte hash (no accidental collisions)', () => {
    const all = Object.values(I).map((v) => v.expectedChallengeHex)
    expect(new Set(all).size).toBe(all.length)
    for (const h of all) expect(h).toMatch(/^[0-9a-f]{64}$/)
  })
})
