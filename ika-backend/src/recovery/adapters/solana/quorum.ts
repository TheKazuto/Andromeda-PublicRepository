/** Quorum recovery via PDA staging — open / contribute / finalize / close. */

import { address as toAddress, type Address } from '@solana/kit'

import { logger } from '../../../logger.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../../../engine/gas-sponsor.js'
import {
  buildQuorumSessionCloseInstruction,
  buildQuorumSessionContributeInstruction,
  buildQuorumSessionContributeWebauthnInstruction,
  buildQuorumSessionFinalizeInstruction,
  buildQuorumSessionOpenInstruction,
  findCpiAuthorityPda,
  findEventAuthorityPda,
  findMessageApprovalPda,
  findQuorumSessionPda,
  findRulesPolicyPda,
  SCHEME_WEBAUTHN,
} from '../../../clients/rulesPolicy/index.js'
import { quorumContributeChallenge, quorumSessionOpenChallenge } from '../../challenge.js'
import type {
  CloseSessionResult,
  ContributeChallengeInput,
  ContributeChallengeOutput,
  ContributeResult,
  ContributeSubmitInput,
  FinalizeSessionResult,
  OpenSessionChallenge,
  OpenSessionInput,
  OpenSessionResult,
  OpenSessionSubmitInput,
} from '../PolicyAdapter.js'
import {
  type SolanaCtx,
  addressBytes,
  buildCredentialPrecompile,
  memberSlotFromCanonical,
  memberSlotToCanonical,
} from './internal.js'
import { fetchPolicyAccount, readQuorumSession } from './state.js'

// ── Session open ────────────────────────────────────────────────

export async function prepareQuorumSessionOpen(
  ctx: SolanaCtx,
  input: OpenSessionInput,
): Promise<OpenSessionChallenge> {
  const programId = ctx.programId
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  const sessionPda = await findQuorumSessionPda(programId, dwallet, decoded.nextSessionNonce)
  const messageApproval = await findMessageApprovalPda(ctx.ikaProgramId, dwallet, input.messageDigest)
  const expiresAt = BigInt(Math.floor(input.expiresAt.getTime() / 1000))
  const result = quorumSessionOpenChallenge({
    dwallet: addressBytes(input.dwalletAddress),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    amount: input.amount,
    destination: input.destination,
    expiresAt,
    sessionNonce: decoded.nextSessionNonce,
    primarySlot: decoded.primarySlot.raw,
  })
  return {
    challenge: result.hash,
    humanMessage: result.humanMessage,
    clearSigning: result.clearSigning,
    expectedSessionNonce: decoded.nextSessionNonce,
    primaryScheme: decoded.primarySlot.scheme,
    sessionAddress: sessionPda.address,
  }
}

export async function submitQuorumSessionOpen(
  ctx: SolanaCtx,
  input: OpenSessionSubmitInput,
): Promise<OpenSessionResult> {
  const programId = ctx.programId
  const dwallet = toAddress(input.dwalletAddress)
  const payer = getGasSponsorAddress()
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  if (decoded.nextSessionNonce !== input.expectedSessionNonce) {
    throw new Error(`Session nonce mismatch: expected ${decoded.nextSessionNonce}, got ${input.expectedSessionNonce}`)
  }
  if (decoded.primarySlot.scheme === SCHEME_WEBAUTHN) {
    throw new Error('Primary cannot use WebAuthn scheme')
  }

  const ikaProgramId = ctx.ikaProgramId
  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const messageApproval = await findMessageApprovalPda(ikaProgramId, dwallet, input.messageDigest)
  const sessionPda = await findQuorumSessionPda(programId, dwallet, decoded.nextSessionNonce)
  const expiresAt = BigInt(Math.floor(input.expiresAt.getTime() / 1000))

  const { hash: challenge } = quorumSessionOpenChallenge({
    dwallet: addressBytes(input.dwalletAddress),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    amount: input.amount,
    destination: input.destination,
    expiresAt,
    sessionNonce: decoded.nextSessionNonce,
    primarySlot: decoded.primarySlot.raw,
  })

  const precompileIx = buildCredentialPrecompile(
    memberSlotFromCanonical(decoded.primarySlot.raw),
    challenge,
    input.primarySignature,
  )

  const mainIx = buildQuorumSessionOpenInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: sessionPda.address,
    payer,
    initAuthorityHash: input.initAuthorityHash,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    amount: input.amount,
    destination: input.destination,
    expiresAt,
  })

  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.quorum.open', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info(
    { dwallet: input.dwalletAddress, sessionAddress: sessionPda.address, txSignature: sig },
    'SolanaAdapter.submitQuorumSessionOpen: session opened',
  )
  return { sessionAddress: sessionPda.address, txSignature: sig }
}

// ── Contribute ──────────────────────────────────────────────────

export async function prepareQuorumContribute(
  input: ContributeChallengeInput,
): Promise<ContributeChallengeOutput> {
  const session = await readQuorumSession(input.sessionAddress)
  if (!session) throw new Error('Session not found on-chain')
  if (input.memberIndex < 0 || input.memberIndex >= session.membersSnapshot.length) {
    throw new Error('memberIndex out of range for session snapshot')
  }
  const slot = session.membersSnapshot[input.memberIndex]!
  const result = quorumContributeChallenge({
    session: addressBytes(input.sessionAddress),
    memberSlot: memberSlotToCanonical(slot),
    dwallet: addressBytes(session.dwalletAddress),
    amount: session.amount,
    destination: session.destination,
    messageDigest: session.messageDigest,
    metadataDigest: session.metadataDigest,
    userPubkey: session.userPubkey,
    signatureScheme: session.signatureScheme,
    messageApprovalBump: session.messageApprovalBump,
    expiresAt: BigInt(Math.floor(session.expiresAt.getTime() / 1000)),
  })
  return {
    challenge: result.hash,
    humanMessage: result.humanMessage,
    clearSigning: result.clearSigning,
    memberSlot: slot,
  }
}

export async function submitQuorumContribute(
  ctx: SolanaCtx,
  input: ContributeSubmitInput,
): Promise<ContributeResult> {
  const programId = ctx.programId
  const session = await readQuorumSession(input.sessionAddress)
  if (!session) throw new Error('Session not found on-chain')
  if (session.finalizedAt) throw new Error('Session already finalized')
  if (session.expiresAt.getTime() <= Date.now()) throw new Error('Session expired')
  if (input.memberIndex < 0 || input.memberIndex >= session.membersSnapshot.length) {
    throw new Error('memberIndex out of range for session snapshot')
  }
  const bit = 1 << input.memberIndex
  if ((session.contributionsBitmap & bit) !== 0) {
    throw new Error('Member already contributed')
  }

  const slot = session.membersSnapshot[input.memberIndex]!
  const { hash: challenge } = quorumContributeChallenge({
    session: addressBytes(input.sessionAddress),
    memberSlot: memberSlotToCanonical(slot),
    dwallet: addressBytes(session.dwalletAddress),
    amount: session.amount,
    destination: session.destination,
    messageDigest: session.messageDigest,
    metadataDigest: session.metadataDigest,
    userPubkey: session.userPubkey,
    signatureScheme: session.signatureScheme,
    messageApprovalBump: session.messageApprovalBump,
    expiresAt: BigInt(Math.floor(session.expiresAt.getTime() / 1000)),
  })

  const precompileIx = buildCredentialPrecompile(
    slot,
    challenge,
    input.memberSignature,
    input.webauthnAuthData,
    input.webauthnClientDataJson,
  )

  const dwallet = session.dwalletAddress
  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const payer = getGasSponsorAddress()

  const mainIx =
    slot.scheme === SCHEME_WEBAUTHN
      ? buildQuorumSessionContributeWebauthnInstruction({
          programId,
          policyPda: policyPda.address,
          dwallet,
          sessionPda: input.sessionAddress,
          payer,
          initAuthorityHash: input.initAuthorityHash,
          memberIndex: input.memberIndex,
          webauthnAuthData: input.webauthnAuthData ?? new Uint8Array(),
          webauthnClientDataJson: input.webauthnClientDataJson ?? new Uint8Array(),
        })
      : buildQuorumSessionContributeInstruction({
          programId,
          policyPda: policyPda.address,
          dwallet,
          sessionPda: input.sessionAddress,
          payer,
          initAuthorityHash: input.initAuthorityHash,
          memberIndex: input.memberIndex,
        })

  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.quorum.contribute', {
    dwalletAddress: dwallet,
    policyAddress: policyPda.address,
  })
  logger.info(
    { sessionAddress: input.sessionAddress, memberIndex: input.memberIndex, txSignature: sig },
    'SolanaAdapter.submitQuorumContribute: contribution recorded',
  )
  return {
    txSignature: sig,
    contributionsCount: session.contributionsCount + 1,
    thresholdRequired: session.thresholdRequired,
  }
}

// ── Finalize / close ────────────────────────────────────────────

export async function submitQuorumFinalizeWithHash(
  ctx: SolanaCtx,
  input: { sessionAddress: Address; dwalletAddress: Address; initAuthorityHash: Uint8Array },
): Promise<FinalizeSessionResult> {
  const programId = ctx.programId
  const ikaProgramId = ctx.ikaProgramId
  const coordinator = ctx.coordinator()
  const session = await readQuorumSession(input.sessionAddress)
  if (!session) throw new Error('Session not found on-chain')
  if (session.finalizedAt) throw new Error('Session already finalized')
  if (session.contributionsCount < session.thresholdRequired) {
    throw new Error('Quorum threshold not met')
  }

  const dwallet = session.dwalletAddress
  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const cpiAuthorityPda = await findCpiAuthorityPda(programId)
  const eventAuthorityPda = await findEventAuthorityPda(programId)
  const messageApproval = await findMessageApprovalPda(ikaProgramId, dwallet, session.messageDigest)
  const payer = getGasSponsorAddress()

  const ix = buildQuorumSessionFinalizeInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: input.sessionAddress,
    coordinator,
    messageApproval: messageApproval.address,
    payer,
    cpiAuthorityPda: cpiAuthorityPda.address,
    ikaProgramId,
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthorityHash: input.initAuthorityHash,
    cpiAuthorityBump: cpiAuthorityPda.bump,
  })

  const sig = await signAndSendInstructions([ix], 'recovery.quorum.finalize', {
    dwalletAddress: dwallet,
    policyAddress: policyPda.address,
  })
  logger.info(
    { sessionAddress: input.sessionAddress, txSignature: sig, messageApproval: messageApproval.address },
    'SolanaAdapter.submitQuorumFinalizeWithHash: session finalized',
  )
  return { txSignature: sig, messageApprovalAddress: messageApproval.address }
}

export async function submitQuorumCloseWithHash(
  ctx: SolanaCtx,
  input: { sessionAddress: Address; dwalletAddress: Address; initAuthorityHash: Uint8Array },
): Promise<CloseSessionResult> {
  const programId = ctx.programId
  const session = await readQuorumSession(input.sessionAddress)
  if (!session) throw new Error('Session not found on-chain')
  const dwallet = session.dwalletAddress
  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const ix = buildQuorumSessionCloseInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: input.sessionAddress,
    initAuthorityHash: input.initAuthorityHash,
    // The on-chain handler enforces `rentDestination == session.payer_for_close`,
    // which is the gas sponsor (it funded the session at open time).
    rentDestination: getGasSponsorAddress(),
  })
  const sig = await signAndSendInstructions([ix], 'recovery.quorum.close', {
    dwalletAddress: dwallet,
    policyAddress: policyPda.address,
  })
  return { txSignature: sig }
}
