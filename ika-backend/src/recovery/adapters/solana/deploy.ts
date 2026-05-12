/** `rules-policy` deploy flow (Audit C2 / Opção 4 — init_authority-seeded PDA). */

import { address as toAddress } from '@solana/kit'

import { logger } from '../../../logger.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../../../engine/gas-sponsor.js'
import {
  buildInitPolicyInstruction,
  findEventAuthorityPda,
  findRulesPolicyPda,
  SCHEME_WEBAUTHN,
} from '../../../clients/rulesPolicy/index.js'
import { initAuthorityHashFromSlot, rulesPolicyInitChallenge } from '../../challenge.js'
import type { DeployInput, DeployResult, MemberSlot } from '../PolicyAdapter.js'
import {
  type SolanaCtx,
  addressBytes,
  buildCredentialPrecompile,
  memberSlotFromCanonical,
  memberSlotToCanonical,
} from './internal.js'

export async function deployRulesPolicy(ctx: SolanaCtx, input: DeployInput): Promise<DeployResult> {
  const cfg = input.config
  if (cfg.cooldownSeconds < ctx.minCooldownSeconds) {
    throw new Error(`cooldown_seconds below MIN_COOLDOWN_SECONDS=${ctx.minCooldownSeconds}`)
  }
  if (cfg.members.length > 0) {
    throw new Error('Deploy cannot pre-seed quorum members; deploy first, then add members through admin actions')
  }
  if (cfg.allowedDestinations !== null) {
    throw new Error(
      'Deploy cannot pre-seed allowed destinations; deploy first, then add destinations through admin actions',
    )
  }
  if (cfg.quorumThreshold < 1 || cfg.quorumThreshold > Math.max(1, cfg.members.length)) {
    throw new Error('Invalid quorum threshold')
  }
  if (cfg.primary.scheme === SCHEME_WEBAUTHN) {
    throw new Error('Primary cannot use WebAuthn scheme; use raw Secp256r1 for passkey primary')
  }

  // Audit C2 (Opção 4): validate the caller-provided init_authority slot,
  // compute its hash, and build the precompile signature for the canonical
  // init challenge. Without these, the on-chain handler rejects.
  if (input.initAuthoritySlot.length !== 34) {
    throw new Error('init_authority_slot must be 34 bytes')
  }
  const initAuthorityHash = initAuthorityHashFromSlot(input.initAuthoritySlot)
  const initAuthoritySlotBuf = input.initAuthoritySlot

  const programId = ctx.programId
  const dwallet = toAddress(input.dwalletAddress)
  const payer = getGasSponsorAddress()
  const policyPda = await findRulesPolicyPda(programId, dwallet, initAuthorityHash)
  const eventAuthorityPda = await findEventAuthorityPda(programId)

  const primarySlot = memberSlotToCanonical(cfg.primary)

  // Audit C2 (Opção 4): the canonical init challenge is bound to
  // (dwallet, init_authority, primary, threshold, daily_limit, cooldown,
  // allowed_destinations_flag); the precompile proves the init_authority signed
  // those exact bytes off-chain.
  const challenge = rulesPolicyInitChallenge({
    dwallet: addressBytes(dwallet),
    initAuthoritySlot: initAuthoritySlotBuf,
    primarySlot,
    quorumThreshold: cfg.quorumThreshold,
    dailyLimitSome: cfg.dailyLimit !== null,
    dailyLimit: cfg.dailyLimit ?? 0n,
    cooldownSeconds: BigInt(cfg.cooldownSeconds),
    allowedDestinationsSome: cfg.allowedDestinations !== null,
  })
  const initSlotMember: MemberSlot = memberSlotFromCanonical(initAuthoritySlotBuf)
  const preIx = buildCredentialPrecompile(
    initSlotMember,
    challenge,
    input.initAuthoritySignature,
    input.initAuthorityWebauthnAuthData,
    input.initAuthorityWebauthnClientDataJson,
  )

  const initIx = buildInitPolicyInstruction({
    programId,
    policyPda: policyPda.address,
    dwallet,
    payer,
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthoritySlot: initAuthoritySlotBuf,
    initAuthorityHash,
    primarySlot,
    quorumThreshold: cfg.quorumThreshold,
    dailyLimitSome: cfg.dailyLimit !== null,
    dailyLimit: cfg.dailyLimit ?? 0n,
    cooldownSeconds: BigInt(cfg.cooldownSeconds),
    allowedDestinationsSome: cfg.allowedDestinations !== null,
  })

  const sig = await signAndSendInstructions([preIx, initIx], 'policy.deploy', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info(
    { dwallet: input.dwalletAddress, policyPda: policyPda.address, txSignature: sig },
    'SolanaAdapter.deployRulesPolicy: policy deployed',
  )
  return { policyAddress: policyPda.address, txSignature: sig, initAuthorityHash }
}
