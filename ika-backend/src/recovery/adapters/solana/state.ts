/** On-chain read path for the Solana `rules-policy` adapter. */

import type { Address } from '@solana/kit'

import { logger } from '../../../logger.js'
import { getSolanaRpc } from '../../../engine/solana-rpc.js'
import {
  decodeQuorumSessionAccount,
  decodeRulesPolicyAccount,
  findRulesPolicyPda,
  type RulesPolicyAccountData,
} from '../../../clients/rulesPolicy/index.js'
import type { PolicyState, QuorumSessionState } from '../PolicyAdapter.js'
import {
  type SolanaCtx,
  addrDecoder,
  memberSlotFromCanonical,
  memberSlotFromData,
  pendingChangeFromState,
} from './internal.js'

/** Fetch and base64-decode an account's data; `null` if the account doesn't exist or carries no string data. */
async function readAccountBytes(address: Address): Promise<Uint8Array | null> {
  const result = await getSolanaRpc()
    .getAccountInfo(address, { encoding: 'base64', commitment: 'confirmed' })
    .send()
  if (!result.value) return null
  const dataField = result.value.data
  const base64 = Array.isArray(dataField) ? dataField[0] : dataField
  if (typeof base64 !== 'string') return null
  return Uint8Array.from(Buffer.from(base64, 'base64'))
}

/** Read and decode the on-chain `rules-policy` account, throwing if absent. */
export async function fetchPolicyAccount(
  ctx: SolanaCtx,
  dwallet: Address,
  initAuthorityHash: Uint8Array,
): Promise<RulesPolicyAccountData> {
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, initAuthorityHash)
  const bytes = await readAccountBytes(policyPda.address)
  if (!bytes || bytes.length === 0) throw new Error('Policy state not found on-chain')
  return decodeRulesPolicyAccount(bytes)
}

/** Public read used by `GET /v1/recovery/policy/:dwalletAddress` — returns `null` for missing/undecodable. */
export async function readPolicyState(
  ctx: SolanaCtx,
  input: { dwalletAddress: Address; initAuthorityHash: Uint8Array },
): Promise<PolicyState | null> {
  const policyPda = await findRulesPolicyPda(ctx.programId, input.dwalletAddress, input.initAuthorityHash)
  const bytes = await readAccountBytes(policyPda.address)
  if (!bytes) return null

  let decoded: RulesPolicyAccountData
  try {
    decoded = decodeRulesPolicyAccount(bytes)
  } catch (err) {
    logger.warn({ err, dwalletAddress: input.dwalletAddress }, 'SolanaAdapter.readStateByHash: decode failed')
    return null
  }

  return {
    policyAddress: policyPda.address,
    dwalletAddress: input.dwalletAddress,
    primary: memberSlotFromCanonical(decoded.primarySlot.raw),
    members: decoded.members.map((m) => memberSlotFromData(m)),
    quorumThreshold: decoded.quorumThreshold,
    dailyLimit: decoded.dailyLimitSome === 1 ? decoded.dailyLimit : null,
    allowedDestinations: decoded.allowedDestinationsSome === 1 ? decoded.allowedDestinations : null,
    cooldownSeconds: Number(decoded.policyChangeCooldownSeconds),
    pendingChange: pendingChangeFromState(decoded),
    dailyUsed: decoded.dailyUsed,
    lastResetTs: new Date(Number(decoded.lastResetTs) * 1000),
    nextAdminNonce: decoded.nextAdminNonce,
    nextPrimaryRecoverNonce: decoded.nextPrimaryRecoverNonce,
    nextSessionNonce: decoded.nextSessionNonce,
  }
}

export async function readQuorumSession(sessionAddress: Address): Promise<QuorumSessionState | null> {
  const bytes = await readAccountBytes(sessionAddress)
  if (!bytes) return null
  try {
    const decoded = decodeQuorumSessionAccount(bytes)
    return {
      sessionAddress,
      dwalletAddress: addrDecoder.decode(decoded.dwallet) as Address,
      policyAddress: addrDecoder.decode(decoded.policy) as Address,
      sessionNonce: decoded.sessionNonce,
      messageDigest: decoded.messageDigest,
      metadataDigest: decoded.metadataDigest,
      userPubkey: decoded.userPubkey,
      signatureScheme: decoded.signatureScheme,
      messageApprovalBump: decoded.messageApprovalBump,
      amount: decoded.amount,
      destination: decoded.destination,
      membersSnapshot: decoded.membersSnapshot.map((m) => memberSlotFromData(m)),
      thresholdRequired: decoded.thresholdSnapshot,
      contributionsCount: decoded.contributionsCount,
      contributionsBitmap: decoded.contributionsBitmap,
      expiresAt: new Date(Number(decoded.expiresAt) * 1000),
      finalizedAt: decoded.finalizedAt === 0n ? null : new Date(Number(decoded.finalizedAt) * 1000),
    }
  } catch (err) {
    logger.warn({ err, sessionAddress }, 'SolanaAdapter.readSession: decode failed')
    return null
  }
}
