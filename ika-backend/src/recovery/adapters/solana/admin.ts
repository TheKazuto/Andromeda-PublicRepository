/** Policy admin actions (challenge-based) + the no-auth `apply_pending` gate. */

import { address as toAddress, type Address, type Instruction } from '@solana/kit'

import { logger } from '../../../logger.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../../../engine/gas-sponsor.js'
import {
  buildAddDestinationInstruction,
  buildAddMemberInstruction,
  buildApplyPendingChangeInstruction,
  buildProposeCooldownChangeInstruction,
  buildProposeDailyLimitChangeInstruction,
  buildProposeQuorumThresholdChangeInstruction,
  buildRemoveDestinationInstruction,
  buildRemoveMemberInstruction,
  buildRevokeInstruction,
  buildSetCooldownImmediateInstruction,
  buildSetDailyLimitImmediateInstruction,
  buildSetPrimaryInstruction,
  buildSetQuorumThresholdImmediateInstruction,
  findRulesPolicyPda,
  SCHEME_WEBAUTHN,
} from '../../../clients/rulesPolicy/index.js'
import {
  adminAddDestinationChallenge,
  adminAddMemberChallenge,
  adminProposeCooldownChallenge,
  adminProposeDailyLimitChallenge,
  adminProposeQuorumThresholdChallenge,
  adminRemoveDestinationChallenge,
  adminRemoveMemberChallenge,
  adminRevokeChallenge,
  adminSetCooldownImmediateChallenge,
  adminSetDailyLimitImmediateChallenge,
  adminSetPrimaryChallenge,
  adminSetQuorumThresholdImmediateChallenge,
} from '../../challenge.js'
import type {
  AdminAction,
  AdminChallengeInput,
  AdminChallengeOutput,
  AdminSubmitInput,
  TxResult,
} from '../PolicyAdapter.js'
import { type SolanaCtx, addressBytes, buildCredentialPrecompile, memberSlotFromCanonical, memberSlotToCanonical } from './internal.js'
import { fetchPolicyAccount } from './state.js'

// ── Challenge computation ───────────────────────────────────────

export function computeAdminChallenge(
  action: AdminAction,
  dwallet: Uint8Array,
  nonce: bigint,
  primarySlot: Uint8Array,
): Uint8Array {
  switch (action.type) {
    case 'add_member':
      return adminAddMemberChallenge({ dwallet, newMemberSlot: memberSlotToCanonical(action.member), nonce, primarySlot })
    case 'remove_member':
      return adminRemoveMemberChallenge({ dwallet, memberSlotToRemove: memberSlotToCanonical(action.member), nonce, primarySlot })
    case 'add_destination':
      return adminAddDestinationChallenge({ dwallet, destination: action.destination, nonce, primarySlot })
    case 'remove_destination':
      return adminRemoveDestinationChallenge({ dwallet, destination: action.destination, nonce, primarySlot })
    case 'revoke':
      return adminRevokeChallenge({ dwallet, nonce, primarySlot })
    case 'set_primary':
      return adminSetPrimaryChallenge({ dwallet, newPrimarySlot: memberSlotToCanonical(action.newPrimary), nonce, currentPrimarySlot: primarySlot })
    case 'set_quorum_threshold_immediate':
      return adminSetQuorumThresholdImmediateChallenge({ dwallet, newThreshold: action.newThreshold, nonce, primarySlot })
    case 'set_daily_limit_immediate':
      return adminSetDailyLimitImmediateChallenge({ dwallet, newSome: action.newSome, newLimit: action.newLimit, nonce, primarySlot })
    case 'set_cooldown_immediate':
      return adminSetCooldownImmediateChallenge({ dwallet, newCooldownSeconds: action.newCooldownSeconds, nonce, primarySlot })
    case 'propose_quorum_threshold_change':
      return adminProposeQuorumThresholdChallenge({ dwallet, newThreshold: action.newThreshold, nonce, primarySlot })
    case 'propose_daily_limit_change':
      return adminProposeDailyLimitChallenge({ dwallet, newSome: action.newSome, newLimit: action.newLimit, nonce, primarySlot })
    case 'propose_cooldown_change':
      return adminProposeCooldownChallenge({ dwallet, newCooldownSeconds: action.newCooldownSeconds, nonce, primarySlot })
  }
}

// ── Main instruction builder ────────────────────────────────────

interface AdminBaseAccounts {
  programId: Address
  policyPda: Address
  dwallet: Address
  payer: Address
  /** Audit C2 (Opção 4): forwarded to every admin instruction encoder. */
  initAuthorityHash: Uint8Array
}

function buildAdminMainInstruction(action: AdminAction, base: AdminBaseAccounts, expectedNonce: bigint): Instruction {
  switch (action.type) {
    case 'add_member':
      return buildAddMemberInstruction({ ...base, newMemberSlot: memberSlotToCanonical(action.member), expectedNonce })
    case 'remove_member':
      return buildRemoveMemberInstruction({ ...base, memberSlotToRemove: memberSlotToCanonical(action.member), expectedNonce })
    case 'add_destination':
      return buildAddDestinationInstruction({ ...base, destination: action.destination, expectedNonce })
    case 'remove_destination':
      return buildRemoveDestinationInstruction({ ...base, destination: action.destination, expectedNonce })
    case 'revoke':
      return buildRevokeInstruction({ ...base, expectedNonce })
    case 'set_primary':
      return buildSetPrimaryInstruction({ ...base, newPrimarySlot: memberSlotToCanonical(action.newPrimary), expectedNonce })
    case 'set_quorum_threshold_immediate':
      return buildSetQuorumThresholdImmediateInstruction({ ...base, newThreshold: action.newThreshold, expectedNonce })
    case 'set_daily_limit_immediate':
      return buildSetDailyLimitImmediateInstruction({ ...base, newSome: action.newSome, newLimit: action.newLimit, expectedNonce })
    case 'set_cooldown_immediate':
      return buildSetCooldownImmediateInstruction({ ...base, newCooldownSeconds: action.newCooldownSeconds, expectedNonce })
    case 'propose_quorum_threshold_change':
      return buildProposeQuorumThresholdChangeInstruction({ ...base, newThreshold: action.newThreshold, expectedNonce })
    case 'propose_daily_limit_change':
      return buildProposeDailyLimitChangeInstruction({ ...base, newSome: action.newSome, newLimit: action.newLimit, expectedNonce })
    case 'propose_cooldown_change':
      return buildProposeCooldownChangeInstruction({ ...base, newCooldownSeconds: action.newCooldownSeconds, expectedNonce })
  }
}

// ── Flows ───────────────────────────────────────────────────────

export async function prepareAdminAction(ctx: SolanaCtx, input: AdminChallengeInput): Promise<AdminChallengeOutput> {
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  const challenge = computeAdminChallenge(
    input.action,
    addressBytes(input.dwalletAddress),
    decoded.nextAdminNonce,
    decoded.primarySlot.raw,
  )
  return { challenge, expectedNonce: decoded.nextAdminNonce }
}

export async function submitAdminAction(ctx: SolanaCtx, input: AdminSubmitInput): Promise<TxResult> {
  const programId = ctx.programId
  const dwallet = toAddress(input.dwalletAddress)
  const payer = getGasSponsorAddress()
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  if (decoded.nextAdminNonce !== input.expectedNonce) {
    throw new Error(`Admin nonce mismatch: expected ${decoded.nextAdminNonce}, got ${input.expectedNonce}`)
  }
  if (decoded.primarySlot.scheme === SCHEME_WEBAUTHN) {
    throw new Error('Primary cannot use WebAuthn scheme')
  }

  const challenge = computeAdminChallenge(
    input.action,
    addressBytes(input.dwalletAddress),
    decoded.nextAdminNonce,
    decoded.primarySlot.raw,
  )
  const precompileIx = buildCredentialPrecompile(
    memberSlotFromCanonical(decoded.primarySlot.raw),
    challenge,
    input.primarySignature,
  )

  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const baseAccounts: AdminBaseAccounts = {
    programId,
    policyPda: policyPda.address,
    dwallet,
    payer,
    initAuthorityHash: input.initAuthorityHash,
  }

  const mainIx = buildAdminMainInstruction(input.action, baseAccounts, input.expectedNonce)
  const sig = await signAndSendInstructions([precompileIx, mainIx], `policy.admin.${input.action.type}`, {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info(
    { dwallet: input.dwalletAddress, action: input.action.type, txSignature: sig },
    'SolanaAdapter.submitAdminAction: admin action applied',
  )
  return { txSignature: sig }
}

export async function applyPendingChange(
  ctx: SolanaCtx,
  input: { dwalletAddress: Address; initAuthorityHash: Uint8Array },
): Promise<TxResult> {
  const programId = ctx.programId
  const dwallet = toAddress(input.dwalletAddress)
  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const ix = buildApplyPendingChangeInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    initAuthorityHash: input.initAuthorityHash,
  })
  const sig = await signAndSendInstructions([ix], 'policy.apply_pending', {
    dwalletAddress: dwallet,
    policyAddress: policyPda.address,
  })
  return { txSignature: sig }
}
