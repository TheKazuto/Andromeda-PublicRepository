/**
 * Mirrors `contracts/auth/src/challenge.rs` byte-for-byte.
 *
 * Every credential — primary OR quorum member — signs the bytes returned by
 * one of these functions. The on-chain handler recomputes the same hash from
 * the same inputs and requires a matching precompile invocation in the
 * transaction. Domain separation + per-operation tags + nonce + member-id
 * binding cover replay across programs / operations / time / members.
 *
 * Frozen golden vectors: `src/recovery/__tests__/challenge_vectors.json`
 * (asserted by `challenge-vectors.test.ts`). Any edit here that changes a
 * hash must update those vectors AND the Rust mirror in the same commit.
 */

import { createHash } from 'node:crypto'

const enc = new TextEncoder()

export const DOMAIN = enc.encode('andromeda::rules-policy::v1')

// Init flow tag (Audit C2 / Opção 4)
export const OP_INIT = enc.encode('init')

// Recovery flow tags
export const OP_PRIMARY_RECOVER = enc.encode('primary-recover')
export const OP_QUORUM_SESSION_OPEN = enc.encode('quorum-session-open')
export const OP_QUORUM_CONTRIBUTE = enc.encode('quorum-contribute')

// Admin flow tags
export const OP_ADMIN_ADD_MEMBER = enc.encode('admin-add-member')
export const OP_ADMIN_REMOVE_MEMBER = enc.encode('admin-remove-member')
export const OP_ADMIN_ADD_DESTINATION = enc.encode('admin-add-destination')
export const OP_ADMIN_REMOVE_DESTINATION = enc.encode('admin-remove-destination')
export const OP_ADMIN_REVOKE = enc.encode('admin-revoke')
export const OP_ADMIN_SET_PRIMARY = enc.encode('admin-set-primary')
export const OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE = enc.encode('admin-set-qt-immediate')
export const OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE = enc.encode('admin-set-dl-immediate')
export const OP_ADMIN_SET_COOLDOWN_IMMEDIATE = enc.encode('admin-set-cd-immediate')
export const OP_ADMIN_PROPOSE_QUORUM_THRESHOLD = enc.encode('admin-propose-qt')
export const OP_ADMIN_PROPOSE_DAILY_LIMIT = enc.encode('admin-propose-dl')
export const OP_ADMIN_PROPOSE_COOLDOWN = enc.encode('admin-propose-cd')

// ── Primitive helpers ──────────────────────────────────────────

function u64Le(v: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, v, true)
  return out
}

function i64Le(v: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigInt64(0, v, true)
  return out
}

function u8Bytes(v: number): Uint8Array {
  return new Uint8Array([v & 0xff])
}

function hashv(parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

// ── Init (Audit C2 / Opção 4) ──────────────────────────────────

/**
 * Init challenge for rules-policy. The init_authority signs this exactly
 * once when creating the policy. Mirrors `contracts/auth/src/challenge.rs::
 * rules_policy_init_challenge`.
 */
export function rulesPolicyInitChallenge(input: {
  dwallet: Uint8Array // 32 bytes
  initAuthoritySlot: Uint8Array // 34 bytes
  primarySlot: Uint8Array // 34 bytes
  quorumThreshold: number
  dailyLimitSome: boolean
  dailyLimit: bigint
  cooldownSeconds: bigint
  allowedDestinationsSome: boolean
}): Uint8Array {
  return hashv([
    DOMAIN,
    OP_INIT,
    input.dwallet,
    input.initAuthoritySlot,
    input.primarySlot,
    u8Bytes(input.quorumThreshold),
    u8Bytes(input.dailyLimitSome ? 1 : 0),
    u64Le(input.dailyLimit),
    u64Le(input.cooldownSeconds),
    u8Bytes(input.allowedDestinationsSome ? 1 : 0),
  ])
}

/**
 * Audit C2 (Opção 4) helper: SHA-256 of the 34-byte init_authority slot.
 * The hash is the third PDA seed for `RulesPolicy`.
 */
export function initAuthorityHashFromSlot(slot: Uint8Array): Uint8Array {
  if (slot.length !== 34) {
    throw new Error(`init_authority_slot must be 34 bytes, got ${slot.length}`)
  }
  return hashv([slot])
}

// ── Recovery ────────────────────────────────────────────────────

export function primaryRecoverChallenge(input: {
  dwallet: Uint8Array // 32 bytes
  messageDigest: Uint8Array // 32 bytes
  metadataDigest: Uint8Array // 32 bytes
  nonce: bigint
  primarySlot: Uint8Array // 34 bytes
}): Uint8Array {
  return hashv([
    DOMAIN,
    OP_PRIMARY_RECOVER,
    input.dwallet,
    input.messageDigest,
    input.metadataDigest,
    u64Le(input.nonce),
    input.primarySlot,
  ])
}

export function quorumSessionOpenChallenge(input: {
  dwallet: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  amount: bigint
  destination: Uint8Array // 32 bytes
  expiresAt: bigint
  sessionNonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return hashv([
    DOMAIN,
    OP_QUORUM_SESSION_OPEN,
    input.dwallet,
    input.messageDigest,
    input.metadataDigest,
    u64Le(input.amount),
    input.destination,
    i64Le(input.expiresAt),
    u64Le(input.sessionNonce),
    input.primarySlot,
  ])
}

export function quorumContributeChallenge(input: {
  session: Uint8Array // 32 bytes (session PDA address)
  memberSlot: Uint8Array // 34 bytes
}): Uint8Array {
  return hashv([DOMAIN, OP_QUORUM_CONTRIBUTE, input.session, input.memberSlot])
}

// ── Admin ───────────────────────────────────────────────────────

function adminHash(
  opTag: Uint8Array,
  dwallet: Uint8Array,
  nonce: bigint,
  primarySlot: Uint8Array,
  extras: Uint8Array[],
): Uint8Array {
  return hashv([DOMAIN, opTag, dwallet, u64Le(nonce), primarySlot, ...extras])
}

export function adminAddMemberChallenge(input: {
  dwallet: Uint8Array
  newMemberSlot: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(OP_ADMIN_ADD_MEMBER, input.dwallet, input.nonce, input.primarySlot, [
    input.newMemberSlot,
  ])
}

export function adminRemoveMemberChallenge(input: {
  dwallet: Uint8Array
  memberSlotToRemove: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(OP_ADMIN_REMOVE_MEMBER, input.dwallet, input.nonce, input.primarySlot, [
    input.memberSlotToRemove,
  ])
}

export function adminAddDestinationChallenge(input: {
  dwallet: Uint8Array
  destination: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(OP_ADMIN_ADD_DESTINATION, input.dwallet, input.nonce, input.primarySlot, [
    input.destination,
  ])
}

export function adminRemoveDestinationChallenge(input: {
  dwallet: Uint8Array
  destination: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(OP_ADMIN_REMOVE_DESTINATION, input.dwallet, input.nonce, input.primarySlot, [
    input.destination,
  ])
}

export function adminRevokeChallenge(input: {
  dwallet: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(OP_ADMIN_REVOKE, input.dwallet, input.nonce, input.primarySlot, [])
}

export function adminSetPrimaryChallenge(input: {
  dwallet: Uint8Array
  newPrimarySlot: Uint8Array
  nonce: bigint
  currentPrimarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_SET_PRIMARY,
    input.dwallet,
    input.nonce,
    input.currentPrimarySlot,
    [input.newPrimarySlot],
  )
}

export function adminSetQuorumThresholdImmediateChallenge(input: {
  dwallet: Uint8Array
  newThreshold: number
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newThreshold)],
  )
}

export function adminSetDailyLimitImmediateChallenge(input: {
  dwallet: Uint8Array
  newSome: boolean
  newLimit: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newSome ? 1 : 0), u64Le(input.newLimit)],
  )
}

export function adminSetCooldownImmediateChallenge(input: {
  dwallet: Uint8Array
  newCooldownSeconds: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_SET_COOLDOWN_IMMEDIATE,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u64Le(input.newCooldownSeconds)],
  )
}

export function adminProposeQuorumThresholdChallenge(input: {
  dwallet: Uint8Array
  newThreshold: number
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_PROPOSE_QUORUM_THRESHOLD,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newThreshold)],
  )
}

export function adminProposeDailyLimitChallenge(input: {
  dwallet: Uint8Array
  newSome: boolean
  newLimit: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_PROPOSE_DAILY_LIMIT,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newSome ? 1 : 0), u64Le(input.newLimit)],
  )
}

export function adminProposeCooldownChallenge(input: {
  dwallet: Uint8Array
  newCooldownSeconds: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): Uint8Array {
  return adminHash(
    OP_ADMIN_PROPOSE_COOLDOWN,
    input.dwallet,
    input.nonce,
    input.primarySlot,
    [u64Le(input.newCooldownSeconds)],
  )
}
