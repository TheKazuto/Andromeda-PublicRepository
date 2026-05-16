// One-off generator for the recovery challenge golden vectors.
//
//   npx tsx scripts/gen-challenge-vectors.ts
//
// Writes src/recovery/__tests__/challenge_vectors.json — the frozen reference
// the `challenge-vectors.test.ts` suite recomputes and asserts against. These
// 14 hashes are also the canonical reference for the Rust mirror in
// contracts/auth/src/challenge.rs (which can only be checked on-chain / via
// litesvm, since that crate's `hashv` deliberately panics off-SBF).
//
// Re-run this and review the diff ONLY when the wire format intentionally
// changes — an unexpected diff means the TS and Rust sides have drifted.

import { writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as C from '../src/recovery/challenge.js'

const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex')
const b = (n: number, fill: number): Uint8Array => new Uint8Array(n).fill(fill)

// Fixed, arbitrary-but-stable inputs. dwallet/session = 32B, slots = 34B,
// digests = 32B, destination = 32B.
const dwallet = b(32, 0x11)
const session = b(32, 0x22)
const policy = b(32, 0x23)
const messageApproval = b(32, 0x24)
const initAuthoritySlot = b(34, 0x33)
const primarySlot = b(34, 0x44)
const newPrimarySlot = b(34, 0x45)
const memberSlot = b(34, 0x55)
const messageDigest = b(32, 0x66)
const metadataDigest = b(32, 0x77)
const destination = b(32, 0x88)
const userPubkey = b(32, 0x99)
const nonce = 42n
const signatureScheme = 5
const messageApprovalBump = 254
const amount = 1_000_000n
const expiresAt = 1_900_000_000n
const dailyLimit = 5_000_000n
const cooldownSeconds = 604_800n
const threshold = 3

const vectors: Record<string, { inputs: Record<string, unknown>; expectedChallengeHex: string }> = {
  rules_policy_init: {
    inputs: { dwallet: hex(dwallet), initAuthoritySlot: hex(initAuthoritySlot), primarySlot: hex(primarySlot), quorumThreshold: threshold, dailyLimitSome: true, dailyLimit: dailyLimit.toString(), cooldownSeconds: cooldownSeconds.toString(), allowedDestinationsSome: false },
    expectedChallengeHex: hex(C.rulesPolicyInitChallenge({ dwallet, initAuthoritySlot, primarySlot, quorumThreshold: threshold, dailyLimitSome: true, dailyLimit, cooldownSeconds, allowedDestinationsSome: false })),
  },
  init_authority_hash_from_slot: {
    inputs: { slot: hex(initAuthoritySlot) },
    expectedChallengeHex: hex(C.initAuthorityHashFromSlot(initAuthoritySlot)),
  },
  primary_recover: {
    inputs: { dwallet: hex(dwallet), messageApproval: hex(messageApproval), messageDigest: hex(messageDigest), metadataDigest: hex(metadataDigest), userPubkey: hex(userPubkey), signatureScheme, messageApprovalBump, nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.primaryRecoverChallenge({ dwallet, messageApproval, messageDigest, metadataDigest, userPubkey, signatureScheme, messageApprovalBump, nonce, primarySlot })),
  },
  quorum_session_open: {
    inputs: { dwallet: hex(dwallet), messageDigest: hex(messageDigest), metadataDigest: hex(metadataDigest), userPubkey: hex(userPubkey), signatureScheme, messageApprovalBump, amount: amount.toString(), destination: hex(destination), expiresAt: expiresAt.toString(), sessionNonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.quorumSessionOpenChallenge({ dwallet, messageDigest, metadataDigest, userPubkey, signatureScheme, messageApprovalBump, amount, destination, expiresAt, sessionNonce: nonce, primarySlot })),
  },
  quorum_contribute: {
    inputs: { session: hex(session), memberSlot: hex(memberSlot) },
    expectedChallengeHex: hex(C.quorumContributeChallenge({ session, memberSlot })),
  },
  admin_add_member: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newMemberSlot: hex(memberSlot), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminAddMemberChallenge({ dwallet, policy, newMemberSlot: memberSlot, nonce, primarySlot })),
  },
  admin_remove_member: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), memberSlotToRemove: hex(memberSlot), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminRemoveMemberChallenge({ dwallet, policy, memberSlotToRemove: memberSlot, nonce, primarySlot })),
  },
  admin_add_destination: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), destination: hex(destination), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminAddDestinationChallenge({ dwallet, policy, destination, nonce, primarySlot })),
  },
  admin_remove_destination: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), destination: hex(destination), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminRemoveDestinationChallenge({ dwallet, policy, destination, nonce, primarySlot })),
  },
  admin_revoke: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminRevokeChallenge({ dwallet, policy, nonce, primarySlot })),
  },
  admin_set_primary: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newPrimarySlot: hex(newPrimarySlot), nonce: nonce.toString(), currentPrimarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminSetPrimaryChallenge({ dwallet, policy, newPrimarySlot, nonce, currentPrimarySlot: primarySlot })),
  },
  admin_set_quorum_threshold_immediate: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newThreshold: threshold, nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminSetQuorumThresholdImmediateChallenge({ dwallet, policy, newThreshold: threshold, nonce, primarySlot })),
  },
  admin_set_daily_limit_immediate: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newSome: true, newLimit: dailyLimit.toString(), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminSetDailyLimitImmediateChallenge({ dwallet, policy, newSome: true, newLimit: dailyLimit, nonce, primarySlot })),
  },
  admin_set_cooldown_immediate: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newCooldownSeconds: cooldownSeconds.toString(), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminSetCooldownImmediateChallenge({ dwallet, policy, newCooldownSeconds: cooldownSeconds, nonce, primarySlot })),
  },
  admin_propose_quorum_threshold: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newThreshold: threshold, nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminProposeQuorumThresholdChallenge({ dwallet, policy, newThreshold: threshold, nonce, primarySlot })),
  },
  admin_propose_daily_limit: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newSome: true, newLimit: dailyLimit.toString(), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminProposeDailyLimitChallenge({ dwallet, policy, newSome: true, newLimit: dailyLimit, nonce, primarySlot })),
  },
  admin_propose_cooldown: {
    inputs: { dwallet: hex(dwallet), policy: hex(policy), newCooldownSeconds: cooldownSeconds.toString(), nonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.adminProposeCooldownChallenge({ dwallet, policy, newCooldownSeconds: cooldownSeconds, nonce, primarySlot })),
  },
  oidc_session_open: {
    inputs: { dwallet: hex(dwallet), primarySlot: hex(primarySlot), ephPk: hex(userPubkey), notAfterUnixTs: expiresAt.toString(), jwtDigest: hex(messageDigest), jwkRegistry: hex(policy), oidcVerifierVersion: 1, sessionNonce: nonce.toString() },
    expectedChallengeHex: hex(C.oidcSessionOpenChallenge({ dwallet, primarySlot, ephPk: userPubkey, notAfterUnixTs: expiresAt, jwtDigest: messageDigest, jwkRegistry: policy, oidcVerifierVersion: 1, sessionNonce: nonce })),
  },
  oidc_primary_use: {
    inputs: { session: hex(session), dwallet: hex(dwallet), messageApproval: hex(messageApproval), messageDigest: hex(messageDigest), metadataDigest: hex(metadataDigest), userPubkey: hex(userPubkey), signatureScheme, messageApprovalBump, useNonce: nonce.toString(), primarySlot: hex(primarySlot) },
    expectedChallengeHex: hex(C.oidcPrimaryUseChallenge({ session, dwallet, messageApproval, messageDigest, metadataDigest, userPubkey, signatureScheme, messageApprovalBump, useNonce: nonce, primarySlot })),
  },
}

const out = {
  _comment:
    'Frozen golden vectors for src/recovery/challenge.ts. Mirrored byte-for-byte by contracts/auth/src/challenge.rs (verified on-chain / via litesvm, not host unit tests). Regenerate with scripts/gen-challenge-vectors.ts and review the diff only on intentional wire-format changes.',
  vectors,
}

const __dirname = dirname(fileURLToPath(import.meta.url))
const outPath = join(__dirname, '..', 'src', 'recovery', '__tests__', 'challenge_vectors.json')
writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${Object.keys(vectors).length} vectors → ${outPath}`)
