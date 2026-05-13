/** Primary-owner recovery flow (single transaction, challenge-based, gas-sponsored). */

import { address as toAddress } from '@solana/kit'

import { logger } from '../../../logger.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../../../engine/gas-sponsor.js'
import {
  buildRecoverAsPrimaryInstruction,
  findCpiAuthorityPda,
  findEventAuthorityPda,
  findMessageApprovalPdaHierarchical,
  findRulesPolicyPda,
  SCHEME_WEBAUTHN,
} from '../../../clients/rulesPolicy/index.js'
import { primaryRecoverChallenge } from '../../challenge.js'
import type {
  PrimaryChallengeInput,
  PrimaryChallengeOutput,
  PrimarySubmitInput,
  PrimarySubmitResult,
} from '../PolicyAdapter.js'
import { type SolanaCtx, addressBytes, buildCredentialPrecompile, memberSlotFromCanonical } from './internal.js'
import { fetchPolicyAccount } from './state.js'

export async function prepareRecoverAsPrimary(
  ctx: SolanaCtx,
  input: PrimaryChallengeInput,
): Promise<PrimaryChallengeOutput> {
  const decoded = await fetchPolicyAccount(ctx, toAddress(input.dwalletAddress), input.initAuthorityHash)
  const dwallet = toAddress(input.dwalletAddress)
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId: ctx.ikaProgramId,
    dwallet,
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })
  const challenge = primaryRecoverChallenge({
    dwallet: addressBytes(input.dwalletAddress),
    messageApproval: addressBytes(messageApproval.address),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    nonce: decoded.nextPrimaryRecoverNonce,
    primarySlot: decoded.primarySlot.raw,
  })
  return {
    challenge,
    expectedNonce: decoded.nextPrimaryRecoverNonce,
    primaryScheme: decoded.primarySlot.scheme,
  }
}

export async function submitRecoverAsPrimary(
  ctx: SolanaCtx,
  input: PrimarySubmitInput,
): Promise<PrimarySubmitResult> {
  const programId = ctx.programId
  const ikaProgramId = ctx.ikaProgramId
  const coordinator = ctx.coordinator()
  const dwallet = toAddress(input.dwalletAddress)
  const payer = getGasSponsorAddress()

  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  if (decoded.nextPrimaryRecoverNonce !== input.expectedNonce) {
    throw new Error(
      `Primary recover nonce mismatch: expected ${decoded.nextPrimaryRecoverNonce}, got ${input.expectedNonce}`,
    )
  }
  const primarySlotData = decoded.primarySlot
  if (primarySlotData.scheme === SCHEME_WEBAUTHN) {
    throw new Error('Primary cannot use WebAuthn scheme')
  }

  const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
  const cpiAuthorityPda = await findCpiAuthorityPda(programId)
  const eventAuthorityPda = await findEventAuthorityPda(programId)
  // Hierarchical seeds — the devnet Ika program rejects the simple form
  // (`signer privilege escalated` on the MessageApproval PDA → 2026-05 smoke test).
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId,
    dwallet,
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })

  const challenge = primaryRecoverChallenge({
    dwallet: addressBytes(input.dwalletAddress),
    messageApproval: addressBytes(messageApproval.address),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    nonce: decoded.nextPrimaryRecoverNonce,
    primarySlot: primarySlotData.raw,
  })

  const precompileIx = buildCredentialPrecompile(
    memberSlotFromCanonical(primarySlotData.raw),
    challenge,
    input.primarySignature,
  )

  const mainIx = buildRecoverAsPrimaryInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    coordinator,
    messageApproval: messageApproval.address,
    payer,
    cpiAuthorityPda: cpiAuthorityPda.address,
    ikaProgramId,
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthorityHash: input.initAuthorityHash,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    cpiAuthorityBump: cpiAuthorityPda.bump,
    expectedNonce: input.expectedNonce,
  })

  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.primary', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info(
    { dwallet: input.dwalletAddress, txSignature: sig },
    'SolanaAdapter.submitRecoverAsPrimary: recovery submitted',
  )
  return { messageApprovalAddress: messageApproval.address, txSignature: sig }
}
