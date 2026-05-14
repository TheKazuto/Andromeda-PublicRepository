/**
 * Mirrors `contracts/auth/src/challenge.rs` byte-for-byte.
 *
 * Every credential — primary OR quorum member OR OIDC ephemeral — signs the
 * bytes returned by one of these functions. The on-chain handler recomputes
 * the same hash from the same inputs and requires a matching precompile
 * invocation in the transaction.
 *
 * Clear-signing v2 wire format (rules-policy DOMAIN bumped to v2):
 *
 * ```text
 * challenge = sha256(
 *   DOMAIN || op_tag
 *   || human_len_u16_le || human_message_bytes
 *   || canonical_typed_params...
 * )
 * ```
 *
 * Each `*Challenge()` function renders the human message internally from
 * the same typed parameters and returns `{ hash, humanMessage, clearSigning }`.
 * Callers MUST surface `humanMessage` to the approver before signing.
 *
 * `OP_INIT` stays at `DOMAIN_INIT_V1` (no clear signing — single-shot,
 * PDA-bound).
 *
 * Frozen golden vectors: `src/recovery/__tests__/challenge_vectors.json`
 * (asserted by `challenge-vectors.test.ts`). Any edit here that changes a
 * hash MUST update those vectors AND the Rust + Go mirrors in the same
 * commit.
 */

import { createHash } from 'node:crypto'
import {
  adminAddDestinationMessage,
  adminAddMemberMessage,
  adminProposeCooldownMessage,
  adminProposeDailyLimitMessage,
  adminProposeQuorumThresholdMessage,
  adminRemoveDestinationMessage,
  adminRemoveMemberMessage,
  adminRevokeMessage,
  adminSetCooldownImmediateMessage,
  adminSetDailyLimitImmediateMessage,
  adminSetPrimaryMessage,
  adminSetQuorumThresholdImmediateMessage,
  base58Encode32,
  CLEAR_SIGNING_VERSION_RULES_POLICY,
  type ClearSigning,
  HumanMessageError,
  MAX_HUMAN_MESSAGE_BYTES,
  oidcPrimaryUseMessage,
  oidcSessionOpenMessage,
  primaryRecoverMessage,
  quorumContributeMessage,
  quorumSessionOpenMessage,
} from './clear_signing.js'

const enc = new TextEncoder()

/** Clear-signing v2 domain (all 17 ops below). */
export const DOMAIN = enc.encode('andromeda::rules-policy::v2')

/** Init-flow domain (preserved at v1 — no clear signing). */
export const DOMAIN_INIT_V1 = enc.encode('andromeda::rules-policy::v1')

// Init flow tag (Audit C2 / Opção 4)
export const OP_INIT = enc.encode('init')

// Recovery flow tags
export const OP_PRIMARY_RECOVER = enc.encode('primary-recover')
export const OP_QUORUM_SESSION_OPEN = enc.encode('quorum-session-open')
export const OP_QUORUM_CONTRIBUTE = enc.encode('quorum-contribute')

// OIDC (Login Social) flow tags
export const OP_OIDC_SESSION_OPEN = enc.encode('oidc-session-open')
export const OP_OIDC_PRIMARY_USE = enc.encode('oidc-primary-use')

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

function u32Le(v: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, v >>> 0, true)
  return out
}

function u16Le(v: number): Uint8Array {
  return new Uint8Array([v & 0xff, (v >> 8) & 0xff])
}

function u8Bytes(v: number): Uint8Array {
  return new Uint8Array([v & 0xff])
}

function hashv(parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

function humanLenLe(human: string): Uint8Array {
  const len = enc.encode(human).length
  if (len > MAX_HUMAN_MESSAGE_BYTES) {
    throw new HumanMessageError('BufferTooSmall')
  }
  return u16Le(len)
}

function humanBytes(human: string): Uint8Array {
  return enc.encode(human)
}

// ── Public result shape ────────────────────────────────────────

export interface ChallengeResult {
  hash: Uint8Array
  humanMessage: string
  clearSigning: ClearSigning
}

// ── Init (Audit C2 / Opção 4) ──────────────────────────────────

/**
 * Init challenge for rules-policy. The init_authority signs this exactly
 * once when creating the policy. Preserved at `DOMAIN_INIT_V1` (no clear
 * signing — init is single-shot per `(dwallet, init_authority_hash)`).
 */
export function rulesPolicyInitChallenge(input: {
  dwallet: Uint8Array
  initAuthoritySlot: Uint8Array
  primarySlot: Uint8Array
  quorumThreshold: number
  dailyLimitSome: boolean
  dailyLimit: bigint
  cooldownSeconds: bigint
  allowedDestinationsSome: boolean
}): Uint8Array {
  return hashv([
    DOMAIN_INIT_V1,
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

// ── Recovery (clear-signing v2) ─────────────────────────────────

export function primaryRecoverChallenge(input: {
  dwallet: Uint8Array
  messageApproval: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = primaryRecoverMessage({
    dwallet: input.dwallet,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
  })
  const hash = hashv([
    DOMAIN,
    OP_PRIMARY_RECOVER,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    input.dwallet,
    input.messageApproval,
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    u16Le(input.signatureScheme),
    u8Bytes(input.messageApprovalBump),
    u64Le(input.nonce),
    input.primarySlot,
  ])
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'primary-recover',
      fields: {
        dwallet: base58Encode32(input.dwallet),
        messageDigestHex: bytesToHex(input.messageDigest),
        metadataDigestHex: bytesToHex(input.metadataDigest),
        userPubkeyHex: bytesToHex(input.userPubkey),
        signatureScheme: input.signatureScheme,
        expectedNonce: input.nonce.toString(),
      },
    },
  }
}

export function quorumSessionOpenChallenge(input: {
  dwallet: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  amount: bigint
  destination: Uint8Array
  expiresAt: bigint
  sessionNonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = quorumSessionOpenMessage({
    dwallet: input.dwallet,
    amount: input.amount,
    destination: input.destination,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    signatureScheme: input.signatureScheme,
    expiresAtUnix: input.expiresAt,
  })
  const hash = hashv([
    DOMAIN,
    OP_QUORUM_SESSION_OPEN,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    input.dwallet,
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    u16Le(input.signatureScheme),
    u8Bytes(input.messageApprovalBump),
    u64Le(input.amount),
    input.destination,
    i64Le(input.expiresAt),
    u64Le(input.sessionNonce),
    input.primarySlot,
  ])
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'quorum-session-open',
      fields: {
        dwallet: base58Encode32(input.dwallet),
        amount: input.amount.toString(),
        destinationHex: bytesToHex(input.destination),
        messageDigestHex: bytesToHex(input.messageDigest),
        metadataDigestHex: bytesToHex(input.metadataDigest),
        signatureScheme: input.signatureScheme,
        expiresAtUnix: input.expiresAt.toString(),
        sessionNonce: input.sessionNonce.toString(),
      },
    },
  }
}

/**
 * Quorum-contribute v2 hashes the full session snapshot used in
 * `approve_message`, so that adulterating any field of the session
 * invalidates every member's signature.
 */
export function quorumContributeChallenge(input: {
  session: Uint8Array
  memberSlot: Uint8Array
  dwallet: Uint8Array
  amount: bigint
  destination: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  expiresAt: bigint
}): ChallengeResult {
  const humanMessage = quorumContributeMessage({
    session: input.session,
    memberSlot: input.memberSlot,
    dwallet: input.dwallet,
    amount: input.amount,
    destination: input.destination,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    expiresAtUnix: input.expiresAt,
  })
  const hash = hashv([
    DOMAIN,
    OP_QUORUM_CONTRIBUTE,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    input.session,
    input.memberSlot,
    input.dwallet,
    u64Le(input.amount),
    input.destination,
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    u16Le(input.signatureScheme),
    u8Bytes(input.messageApprovalBump),
    i64Le(input.expiresAt),
  ])
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'quorum-contribute',
      fields: {
        session: base58Encode32(input.session),
        dwallet: base58Encode32(input.dwallet),
        amount: input.amount.toString(),
        destinationHex: bytesToHex(input.destination),
        messageDigestHex: bytesToHex(input.messageDigest),
        metadataDigestHex: bytesToHex(input.metadataDigest),
        userPubkeyHex: bytesToHex(input.userPubkey),
        signatureScheme: input.signatureScheme,
        expiresAtUnix: input.expiresAt.toString(),
      },
    },
  }
}

// ── OIDC (Login Social, clear-signing v2) ──────────────────────

export function oidcSessionOpenChallenge(input: {
  dwallet: Uint8Array
  primarySlot: Uint8Array
  ephPk: Uint8Array
  notAfterUnixTs: bigint
  jwtDigest: Uint8Array
  jwkRegistry: Uint8Array
  oidcVerifierVersion: number
  sessionNonce: bigint
}): ChallengeResult {
  const humanMessage = oidcSessionOpenMessage({
    dwallet: input.dwallet,
    notAfterUnixTs: input.notAfterUnixTs,
    ephPk: input.ephPk,
  })
  const hash = hashv([
    DOMAIN,
    OP_OIDC_SESSION_OPEN,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    input.dwallet,
    input.primarySlot,
    input.ephPk,
    u64Le(input.notAfterUnixTs),
    input.jwtDigest,
    input.jwkRegistry,
    u32Le(input.oidcVerifierVersion),
    u64Le(input.sessionNonce),
  ])
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'oidc-session-open',
      fields: {
        dwallet: base58Encode32(input.dwallet),
        ephPkHex: bytesToHex(input.ephPk),
        notAfterUnixTs: input.notAfterUnixTs.toString(),
        oidcVerifierVersion: input.oidcVerifierVersion,
        sessionNonce: input.sessionNonce.toString(),
      },
    },
  }
}

export function oidcPrimaryUseChallenge(input: {
  session: Uint8Array
  dwallet: Uint8Array
  messageApproval: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  useNonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = oidcPrimaryUseMessage({
    session: input.session,
    dwallet: input.dwallet,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
  })
  const hash = hashv([
    DOMAIN,
    OP_OIDC_PRIMARY_USE,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    input.session,
    input.dwallet,
    input.messageApproval,
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    u16Le(input.signatureScheme),
    u8Bytes(input.messageApprovalBump),
    u64Le(input.useNonce),
    input.primarySlot,
  ])
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'oidc-primary-use',
      fields: {
        session: base58Encode32(input.session),
        dwallet: base58Encode32(input.dwallet),
        messageDigestHex: bytesToHex(input.messageDigest),
        metadataDigestHex: bytesToHex(input.metadataDigest),
        userPubkeyHex: bytesToHex(input.userPubkey),
        signatureScheme: input.signatureScheme,
        useNonce: input.useNonce.toString(),
      },
    },
  }
}

// ── Admin (primary signs, clear-signing v2) ────────────────────

function adminHashWithHuman(
  opTag: Uint8Array,
  humanMessage: string,
  dwallet: Uint8Array,
  policy: Uint8Array,
  nonce: bigint,
  ownerSlot: Uint8Array,
  extras: Uint8Array[],
): Uint8Array {
  return hashv([
    DOMAIN,
    opTag,
    humanLenLe(humanMessage),
    humanBytes(humanMessage),
    dwallet,
    policy,
    u64Le(nonce),
    ownerSlot,
    ...extras,
  ])
}

function adminFields(
  dwallet: Uint8Array,
  policy: Uint8Array,
  nonce: bigint,
  extra: Record<string, string | number | boolean> = {},
): Record<string, string | number | boolean> {
  return {
    dwallet: base58Encode32(dwallet),
    policy: base58Encode32(policy),
    expectedNonce: nonce.toString(),
    ...extra,
  }
}

export function adminAddMemberChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newMemberSlot: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminAddMemberMessage({
    newMemberSlot: input.newMemberSlot,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_ADD_MEMBER,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [input.newMemberSlot],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-add-member',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newMemberSlotHex: bytesToHex(input.newMemberSlot),
      }),
    },
  }
}

export function adminRemoveMemberChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  memberSlotToRemove: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminRemoveMemberMessage({
    memberSlot: input.memberSlotToRemove,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_REMOVE_MEMBER,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [input.memberSlotToRemove],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-remove-member',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        memberSlotHex: bytesToHex(input.memberSlotToRemove),
      }),
    },
  }
}

export function adminAddDestinationChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  destination: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminAddDestinationMessage({
    destination: input.destination,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_ADD_DESTINATION,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [input.destination],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-add-destination',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        destinationHex: bytesToHex(input.destination),
      }),
    },
  }
}

export function adminRemoveDestinationChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  destination: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminRemoveDestinationMessage({
    destination: input.destination,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_REMOVE_DESTINATION,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [input.destination],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-remove-destination',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        destinationHex: bytesToHex(input.destination),
      }),
    },
  }
}

export function adminRevokeChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminRevokeMessage({ policy: input.policy, dwallet: input.dwallet })
  const hash = adminHashWithHuman(
    OP_ADMIN_REVOKE,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-revoke',
      fields: adminFields(input.dwallet, input.policy, input.nonce),
    },
  }
}

export function adminSetPrimaryChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newPrimarySlot: Uint8Array
  nonce: bigint
  currentPrimarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminSetPrimaryMessage({
    newPrimarySlot: input.newPrimarySlot,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_SET_PRIMARY,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.currentPrimarySlot,
    [input.newPrimarySlot],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-set-primary',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newPrimarySlotHex: bytesToHex(input.newPrimarySlot),
      }),
    },
  }
}

export function adminSetQuorumThresholdImmediateChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newThreshold: number
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminSetQuorumThresholdImmediateMessage({
    newThreshold: input.newThreshold,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_SET_QUORUM_THRESHOLD_IMMEDIATE,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newThreshold)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-set-qt-immediate',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newThreshold: input.newThreshold,
      }),
    },
  }
}

export function adminSetDailyLimitImmediateChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newSome: boolean
  newLimit: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminSetDailyLimitImmediateMessage({
    newSome: input.newSome,
    newLimit: input.newLimit,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_SET_DAILY_LIMIT_IMMEDIATE,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newSome ? 1 : 0), u64Le(input.newLimit)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-set-dl-immediate',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newSome: input.newSome,
        newLimit: input.newLimit.toString(),
      }),
    },
  }
}

export function adminSetCooldownImmediateChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newCooldownSeconds: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminSetCooldownImmediateMessage({
    newCooldownSeconds: input.newCooldownSeconds,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_SET_COOLDOWN_IMMEDIATE,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u64Le(input.newCooldownSeconds)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-set-cd-immediate',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newCooldownSeconds: input.newCooldownSeconds.toString(),
      }),
    },
  }
}

export function adminProposeQuorumThresholdChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newThreshold: number
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminProposeQuorumThresholdMessage({
    newThreshold: input.newThreshold,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_PROPOSE_QUORUM_THRESHOLD,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newThreshold)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-propose-qt',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newThreshold: input.newThreshold,
      }),
    },
  }
}

export function adminProposeDailyLimitChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newSome: boolean
  newLimit: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminProposeDailyLimitMessage({
    newSome: input.newSome,
    newLimit: input.newLimit,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_PROPOSE_DAILY_LIMIT,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u8Bytes(input.newSome ? 1 : 0), u64Le(input.newLimit)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-propose-dl',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newSome: input.newSome,
        newLimit: input.newLimit.toString(),
      }),
    },
  }
}

export function adminProposeCooldownChallenge(input: {
  dwallet: Uint8Array
  policy: Uint8Array
  newCooldownSeconds: bigint
  nonce: bigint
  primarySlot: Uint8Array
}): ChallengeResult {
  const humanMessage = adminProposeCooldownMessage({
    newCooldownSeconds: input.newCooldownSeconds,
    policy: input.policy,
    dwallet: input.dwallet,
  })
  const hash = adminHashWithHuman(
    OP_ADMIN_PROPOSE_COOLDOWN,
    humanMessage,
    input.dwallet,
    input.policy,
    input.nonce,
    input.primarySlot,
    [u64Le(input.newCooldownSeconds)],
  )
  return {
    hash,
    humanMessage,
    clearSigning: {
      version: CLEAR_SIGNING_VERSION_RULES_POLICY,
      operation: 'admin-propose-cd',
      fields: adminFields(input.dwallet, input.policy, input.nonce, {
        newCooldownSeconds: input.newCooldownSeconds.toString(),
      }),
    },
  }
}

// ── Helpers ────────────────────────────────────────────────────

function bytesToHex(b: Uint8Array): string {
  let out = ''
  for (const x of b) {
    const h = x.toString(16)
    out += h.length === 1 ? '0' + h : h
  }
  return out
}
