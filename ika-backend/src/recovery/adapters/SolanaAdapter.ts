/**
 * Concrete `PolicyAdapter` over the Quasar `rules-policy` program (v2).
 *
 * Every flow is challenge-based: the user signs a 32-byte challenge off-chain
 * with whatever wallet/scheme they have, and the adapter builds a Solana
 * transaction containing:
 *   1. The matching precompile instruction (Ed25519 / Secp256k1 / Secp256r1)
 *      whose `(public_key_or_eth_address, message=challenge, signature)`
 *      proves the user's intent to the on-chain runtime.
 *   2. The main `rules-policy` instruction.
 *
 * The transaction's fee payer is the gas sponsor (backend keypair). The
 * user wallet is never required to be a Solana signer.
 */

import {
  address as toAddress,
  getAddressDecoder,
  getAddressEncoder,
  type Address,
  type Instruction,
} from '@solana/kit'
import { createHash } from 'node:crypto'

import { logger } from '../../logger.js'
import { signAndSendInstructions, getGasSponsorAddress } from '../../engine/gas-sponsor.js'
import { getSolanaRpc } from '../../engine/solana-rpc.js'
import {
  buildEd25519PrecompileInstruction,
  buildSecp256k1PrecompileInstruction,
  buildSecp256r1PrecompileInstruction,
} from '../../engine/precompiles.js'
import {
  buildAddDestinationInstruction,
  buildAddMemberInstruction,
  buildApplyPendingChangeInstruction,
  buildInitPolicyInstruction,
  buildProposeCooldownChangeInstruction,
  buildProposeDailyLimitChangeInstruction,
  buildProposeQuorumThresholdChangeInstruction,
  buildQuorumSessionCloseInstruction,
  buildQuorumSessionContributeInstruction,
  buildQuorumSessionContributeWebauthnInstruction,
  buildQuorumSessionFinalizeInstruction,
  buildQuorumSessionOpenInstruction,
  buildRecoverAsPrimaryInstruction,
  buildRemoveDestinationInstruction,
  buildRemoveMemberInstruction,
  buildRevokeInstruction,
  buildSetCooldownImmediateInstruction,
  buildSetDailyLimitImmediateInstruction,
  buildSetPrimaryInstruction,
  buildSetQuorumThresholdImmediateInstruction,
  decodeQuorumSessionAccount,
  decodeRulesPolicyAccount,
  findCpiAuthorityPda,
  findMessageApprovalPda,
  findQuorumSessionPda,
  findRulesPolicyPda,
  type MemberSlotData,
  type RulesPolicyAccountData,
  PENDING_CHANGE_KIND_NONE,
  PENDING_CHANGE_KIND_QUORUM,
  PENDING_CHANGE_KIND_DAILY_LIMIT,
  PENDING_CHANGE_KIND_COOLDOWN,
  SCHEME_ED25519,
  SCHEME_SECP256K1,
  SCHEME_SECP256R1,
  SCHEME_WEBAUTHN,
} from '../../clients/rulesPolicy/index.js'
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
  initAuthorityHashFromSlot,
  primaryRecoverChallenge,
  quorumContributeChallenge,
  quorumSessionOpenChallenge,
  rulesPolicyInitChallenge,
} from '../challenge.js'
import type {
  AdminAction,
  AdminChallengeInput,
  AdminChallengeOutput,
  AdminSubmitInput,
  CloseSessionResult,
  ContributeChallengeInput,
  ContributeChallengeOutput,
  ContributeResult,
  ContributeSubmitInput,
  DeployInput,
  DeployResult,
  FinalizeSessionResult,
  MemberSlot,
  OpenSessionChallenge,
  OpenSessionInput,
  OpenSessionResult,
  OpenSessionSubmitInput,
  PendingChange,
  PolicyAdapter,
  PolicyConfig,
  PolicyState,
  PrimaryChallengeInput,
  PrimaryChallengeOutput,
  PrimarySubmitInput,
  PrimarySubmitResult,
  QuorumSessionState,
  TxResult,
} from './PolicyAdapter.js'

const addrEncoder = getAddressEncoder()
const addrDecoder = getAddressDecoder()

export interface SolanaAdapterOptions {
  programId: string
  ikaProgramId: string
  ikaCoordinatorAddress: string | undefined
  defaultCooldownSeconds: number
  minCooldownSeconds: number
}

// ── Helpers ─────────────────────────────────────────────────────

function addressBytes(addr: Address | string): Uint8Array {
  return addrEncoder.encode(toAddress(addr)) as Uint8Array
}

function memberSlotToCanonical(slot: MemberSlot): Uint8Array {
  const expected = idLen(slot.scheme)
  if (slot.identifier.length !== expected) {
    throw new Error(
      `Identifier length ${slot.identifier.length} does not match scheme ${slot.scheme} (expected ${expected})`,
    )
  }
  const out = new Uint8Array(34)
  out[0] = slot.scheme
  out.set(slot.identifier, 1)
  return out
}

function memberSlotFromCanonical(raw: Uint8Array, label?: string): MemberSlot {
  const scheme = raw[0]!
  const len = idLen(scheme)
  return {
    scheme,
    identifier: raw.slice(1, 1 + len),
    ...(label !== undefined ? { label } : {}),
  }
}

function memberSlotFromData(data: MemberSlotData, label?: string): MemberSlot {
  return { scheme: data.scheme, identifier: data.identifier, ...(label !== undefined ? { label } : {}) }
}

function idLen(scheme: number): number {
  switch (scheme) {
    case SCHEME_ED25519:
      return 32
    case SCHEME_SECP256K1:
      return 20
    case SCHEME_SECP256R1:
    case SCHEME_WEBAUTHN:
      return 33
    default:
      throw new Error(`Unsupported scheme: ${scheme}`)
  }
}

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest())
}

/**
 * Builds the precompile instruction that proves `slot` signed `challenge`.
 * For WebAuthn members, the runtime-signed message is
 * `webauthnAuthData || sha256(webauthnClientDataJson)`, not the raw
 * challenge — the on-chain handler reconstructs it the same way and verifies
 * the challenge appears base64url-no-pad inside the clientDataJSON.
 */
function buildCredentialPrecompile(
  slot: MemberSlot,
  challenge: Uint8Array,
  signature: Uint8Array,
  webauthnAuthData?: Uint8Array,
  webauthnClientDataJson?: Uint8Array,
): Instruction {
  switch (slot.scheme) {
    case SCHEME_ED25519:
      return buildEd25519PrecompileInstruction({
        publicKey: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_SECP256K1:
      return buildSecp256k1PrecompileInstruction({
        ethAddress: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_SECP256R1:
      return buildSecp256r1PrecompileInstruction({
        publicKey: slot.identifier,
        message: challenge,
        signature,
      })
    case SCHEME_WEBAUTHN: {
      if (!webauthnAuthData || !webauthnClientDataJson) {
        throw new Error('WebAuthn member requires authenticatorData and clientDataJSON')
      }
      const cdjHash = sha256(webauthnClientDataJson)
      const signed = new Uint8Array(webauthnAuthData.length + 32)
      signed.set(webauthnAuthData, 0)
      signed.set(cdjHash, webauthnAuthData.length)
      return buildSecp256r1PrecompileInstruction({
        publicKey: slot.identifier,
        message: signed,
        signature,
      })
    }
    default:
      throw new Error(`Unsupported scheme: ${slot.scheme}`)
  }
}

function pendingChangeFromState(data: RulesPolicyAccountData): PendingChange | null {
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_NONE) return null
  const activatesAt = new Date(Number(data.pendingChange.activatesAt) * 1000)
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_QUORUM) {
    return {
      kind: 'quorum_threshold',
      newQuorumThreshold: data.pendingChange.newQuorumThreshold,
      activatesAt,
    }
  }
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_DAILY_LIMIT) {
    return {
      kind: 'daily_limit',
      newDailyLimit:
        data.pendingChange.newDailyLimitSome === 1 ? data.pendingChange.newDailyLimit : null,
      activatesAt,
    }
  }
  if (data.pendingChangeKind === PENDING_CHANGE_KIND_COOLDOWN) {
    return {
      kind: 'cooldown',
      newCooldownSeconds: Number(data.pendingChange.newCooldownSeconds),
      activatesAt,
    }
  }
  return null
}

// ── Adapter ─────────────────────────────────────────────────────

export class SolanaAdapter implements PolicyAdapter {
  constructor(private readonly opts: SolanaAdapterOptions) {}

  private requireProgramId(): Address {
    return toAddress(this.opts.programId)
  }

  private requireIkaProgramId(): Address {
    return toAddress(this.opts.ikaProgramId)
  }

  private requireCoordinator(): Address {
    if (!this.opts.ikaCoordinatorAddress) {
      throw new Error('IKA_COORDINATOR_ADDRESS not configured')
    }
    return toAddress(this.opts.ikaCoordinatorAddress)
  }

  private async readPolicyOrThrow(
    dwallet: Address,
    initAuthorityHash: Uint8Array,
  ): Promise<RulesPolicyAccountData> {
    const programId = this.requireProgramId()
    const policyPda = await findRulesPolicyPda(programId, dwallet, initAuthorityHash)
    const result = await getSolanaRpc()
      .getAccountInfo(policyPda.address, { encoding: 'base64', commitment: 'confirmed' })
      .send()
    if (!result.value) throw new Error('Policy state not found on-chain')
    const dataField = result.value.data
    const base64 = Array.isArray(dataField) ? dataField[0] : dataField
    if (typeof base64 !== 'string') throw new Error('Policy account has no data')
    return decodeRulesPolicyAccount(Uint8Array.from(Buffer.from(base64, 'base64')))
  }

  // ── Deploy ────────────────────────────────────────────────

  async deployRulesPolicy(input: DeployInput): Promise<DeployResult> {
    const cfg = input.config
    if (cfg.cooldownSeconds < this.opts.minCooldownSeconds) {
      throw new Error(`cooldown_seconds below MIN_COOLDOWN_SECONDS=${this.opts.minCooldownSeconds}`)
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

    // Audit C2 (Opção 4): validate caller-provided init_authority slot,
    // compute hash, build precompile signature for the canonical init
    // challenge. Without these, the on-chain handler rejects.
    if (input.initAuthoritySlot.length !== 34) {
      throw new Error('init_authority_slot must be 34 bytes')
    }
    const initAuthorityHash = initAuthorityHashFromSlot(input.initAuthoritySlot)
    const initAuthoritySlotBuf = input.initAuthoritySlot

    const programId = this.requireProgramId()
    const dwallet = toAddress(input.dwalletAddress)
    const payer = getGasSponsorAddress()
    const policyPda = await findRulesPolicyPda(programId, dwallet, initAuthorityHash)

    const primarySlot = memberSlotToCanonical(cfg.primary)

    // Audit C2 (Opção 4): build the canonical init challenge bound to
    // (dwallet, init_authority, primary, threshold, daily_limit, cooldown,
    // allowed_destinations_flag) and the precompile that proves the
    // init_authority signed those exact bytes off-chain.
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

  // ── Read state ────────────────────────────────────────────

  /**
   * @deprecated Audit C2 (Opção 4): a single dwallet can host multiple
   * policies (one per init_authority). Use `readStateByHash` instead — the
   * caller looks up `init_authority_hash` from the local DB.
   */
  async readState(_dwalletAddress: Address): Promise<PolicyState | null> {
    throw new Error(
      'readState(dwalletAddress) is no longer sufficient — use readStateByHash({dwalletAddress, initAuthorityHash}) (Audit C2)',
    )
  }

  async readStateByHash(input: {
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<PolicyState | null> {
    const programId = this.requireProgramId()
    const dwallet = toAddress(input.dwalletAddress)
    const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
    const result = await getSolanaRpc()
      .getAccountInfo(policyPda.address, { encoding: 'base64', commitment: 'confirmed' })
      .send()
    if (!result.value) return null
    const dataField = result.value.data
    const base64 = Array.isArray(dataField) ? dataField[0] : dataField
    if (typeof base64 !== 'string') return null

    let decoded: RulesPolicyAccountData
    try {
      decoded = decodeRulesPolicyAccount(Uint8Array.from(Buffer.from(base64, 'base64')))
    } catch (err) {
      logger.warn({ err, dwalletAddress: input.dwalletAddress }, 'SolanaAdapter.readStateByHash: decode failed')
      return null
    }

    return {
      policyAddress: policyPda.address,
      dwalletAddress: dwallet,
      primary: memberSlotFromCanonical(decoded.primarySlot.raw),
      members: decoded.members.map((m) => memberSlotFromData(m)),
      quorumThreshold: decoded.quorumThreshold,
      dailyLimit: decoded.dailyLimitSome === 1 ? decoded.dailyLimit : null,
      allowedDestinations:
        decoded.allowedDestinationsSome === 1 ? decoded.allowedDestinations : null,
      cooldownSeconds: Number(decoded.policyChangeCooldownSeconds),
      pendingChange: pendingChangeFromState(decoded),
      dailyUsed: decoded.dailyUsed,
      lastResetTs: new Date(Number(decoded.lastResetTs) * 1000),
      nextAdminNonce: decoded.nextAdminNonce,
      nextPrimaryRecoverNonce: decoded.nextPrimaryRecoverNonce,
      nextSessionNonce: decoded.nextSessionNonce,
    }
  }

  async readSession(sessionAddress: Address): Promise<QuorumSessionState | null> {
    const result = await getSolanaRpc()
      .getAccountInfo(sessionAddress, { encoding: 'base64', commitment: 'confirmed' })
      .send()
    if (!result.value) return null
    const dataField = result.value.data
    const base64 = Array.isArray(dataField) ? dataField[0] : dataField
    if (typeof base64 !== 'string') return null
    try {
      const decoded = decodeQuorumSessionAccount(Uint8Array.from(Buffer.from(base64, 'base64')))
      return {
        sessionAddress,
        dwalletAddress: addrDecoder.decode(decoded.dwallet) as Address,
        policyAddress: addrDecoder.decode(decoded.policy) as Address,
        sessionNonce: decoded.sessionNonce,
        messageDigest: decoded.messageDigest,
        metadataDigest: decoded.metadataDigest,
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

  // ── Primary recovery ──────────────────────────────────────

  async prepareRecoverAsPrimary(input: PrimaryChallengeInput): Promise<PrimaryChallengeOutput> {
    const decoded = await this.readPolicyOrThrow(toAddress(input.dwalletAddress), input.initAuthorityHash)
    const challenge = primaryRecoverChallenge({
      dwallet: addressBytes(input.dwalletAddress),
      messageDigest: input.messageDigest,
      metadataDigest: input.metadataDigest,
      nonce: decoded.nextPrimaryRecoverNonce,
      primarySlot: decoded.primarySlot.raw,
    })
    return {
      challenge,
      expectedNonce: decoded.nextPrimaryRecoverNonce,
      primaryScheme: decoded.primarySlot.scheme,
    }
  }

  async submitRecoverAsPrimary(input: PrimarySubmitInput): Promise<PrimarySubmitResult> {
    const programId = this.requireProgramId()
    const ikaProgramId = this.requireIkaProgramId()
    const coordinator = this.requireCoordinator()
    const dwallet = toAddress(input.dwalletAddress)
    const payer = getGasSponsorAddress()

    const decoded = await this.readPolicyOrThrow(dwallet, input.initAuthorityHash)
    if (decoded.nextPrimaryRecoverNonce !== input.expectedNonce) {
      throw new Error(
        `Primary recover nonce mismatch: expected ${decoded.nextPrimaryRecoverNonce}, got ${input.expectedNonce}`,
      )
    }
    const primarySlotData = decoded.primarySlot
    if (primarySlotData.scheme === SCHEME_WEBAUTHN) {
      throw new Error('Primary cannot use WebAuthn scheme')
    }

    const challenge = primaryRecoverChallenge({
      dwallet: addressBytes(input.dwalletAddress),
      messageDigest: input.messageDigest,
      metadataDigest: input.metadataDigest,
      nonce: decoded.nextPrimaryRecoverNonce,
      primarySlot: primarySlotData.raw,
    })

    const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
    const cpiAuthorityPda = await findCpiAuthorityPda(programId)
    const messageApproval = await findMessageApprovalPda(ikaProgramId, dwallet, input.messageDigest)

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
      callerProgram: programId,
      ikaProgramId,
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

  // ── Quorum staging ────────────────────────────────────────

  async prepareQuorumSessionOpen(input: OpenSessionInput): Promise<OpenSessionChallenge> {
    const programId = this.requireProgramId()
    const dwallet = toAddress(input.dwalletAddress)
    const decoded = await this.readPolicyOrThrow(dwallet, input.initAuthorityHash)
    const sessionPda = await findQuorumSessionPda(programId, dwallet, decoded.nextSessionNonce)
    const expiresAt = BigInt(Math.floor(input.expiresAt.getTime() / 1000))
    const challenge = quorumSessionOpenChallenge({
      dwallet: addressBytes(input.dwalletAddress),
      messageDigest: input.messageDigest,
      metadataDigest: input.metadataDigest,
      amount: input.amount,
      destination: input.destination,
      expiresAt,
      sessionNonce: decoded.nextSessionNonce,
      primarySlot: decoded.primarySlot.raw,
    })
    return {
      challenge,
      expectedSessionNonce: decoded.nextSessionNonce,
      primaryScheme: decoded.primarySlot.scheme,
      sessionAddress: sessionPda.address,
    }
  }

  async submitQuorumSessionOpen(input: OpenSessionSubmitInput): Promise<OpenSessionResult> {
    const programId = this.requireProgramId()
    const dwallet = toAddress(input.dwalletAddress)
    const payer = getGasSponsorAddress()
    const decoded = await this.readPolicyOrThrow(dwallet, input.initAuthorityHash)
    if (decoded.nextSessionNonce !== input.expectedSessionNonce) {
      throw new Error(
        `Session nonce mismatch: expected ${decoded.nextSessionNonce}, got ${input.expectedSessionNonce}`,
      )
    }
    if (decoded.primarySlot.scheme === SCHEME_WEBAUTHN) {
      throw new Error('Primary cannot use WebAuthn scheme')
    }

    const ikaProgramId = this.requireIkaProgramId()
    const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
    const messageApproval = await findMessageApprovalPda(ikaProgramId, dwallet, input.messageDigest)
    const sessionPda = await findQuorumSessionPda(programId, dwallet, decoded.nextSessionNonce)
    const expiresAt = BigInt(Math.floor(input.expiresAt.getTime() / 1000))

    const challenge = quorumSessionOpenChallenge({
      dwallet: addressBytes(input.dwalletAddress),
      messageDigest: input.messageDigest,
      metadataDigest: input.metadataDigest,
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

  async prepareQuorumContribute(
    input: ContributeChallengeInput,
  ): Promise<ContributeChallengeOutput> {
    const session = await this.readSession(input.sessionAddress)
    if (!session) throw new Error('Session not found on-chain')
    if (input.memberIndex < 0 || input.memberIndex >= session.membersSnapshot.length) {
      throw new Error('memberIndex out of range for session snapshot')
    }
    const slot = session.membersSnapshot[input.memberIndex]!
    const challenge = quorumContributeChallenge({
      session: addressBytes(input.sessionAddress),
      memberSlot: memberSlotToCanonical(slot),
    })
    return { challenge, memberSlot: slot }
  }

  async submitQuorumContribute(input: ContributeSubmitInput): Promise<ContributeResult> {
    const programId = this.requireProgramId()
    const session = await this.readSession(input.sessionAddress)
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
    const challenge = quorumContributeChallenge({
      session: addressBytes(input.sessionAddress),
      memberSlot: memberSlotToCanonical(slot),
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

  /**
   * @deprecated Audit C2 (Opção 4): use `submitQuorumFinalizeWithHash`.
   */
  async submitQuorumFinalize(_sessionAddress: Address): Promise<FinalizeSessionResult> {
    throw new Error(
      'submitQuorumFinalize(sessionAddress) requires init_authority_hash — use submitQuorumFinalizeWithHash (Audit C2)',
    )
  }

  async submitQuorumFinalizeWithHash(input: {
    sessionAddress: Address
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<FinalizeSessionResult> {
    const programId = this.requireProgramId()
    const ikaProgramId = this.requireIkaProgramId()
    const coordinator = this.requireCoordinator()
    const session = await this.readSession(input.sessionAddress)
    if (!session) throw new Error('Session not found on-chain')
    if (session.finalizedAt) throw new Error('Session already finalized')
    if (session.contributionsCount < session.thresholdRequired) {
      throw new Error('Quorum threshold not met')
    }

    const dwallet = session.dwalletAddress
    const policyPda = await findRulesPolicyPda(programId, dwallet, input.initAuthorityHash)
    const cpiAuthorityPda = await findCpiAuthorityPda(programId)
    const messageApproval = await findMessageApprovalPda(
      ikaProgramId,
      dwallet,
      session.messageDigest,
    )
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
      callerProgram: programId,
      ikaProgramId,
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

  /**
   * @deprecated Audit C2 (Opção 4): use `submitQuorumCloseWithHash`.
   */
  async submitQuorumClose(_sessionAddress: Address): Promise<CloseSessionResult> {
    throw new Error(
      'submitQuorumClose(sessionAddress) requires init_authority_hash — use submitQuorumCloseWithHash (Audit C2)',
    )
  }

  async submitQuorumCloseWithHash(input: {
    sessionAddress: Address
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<CloseSessionResult> {
    const programId = this.requireProgramId()
    const session = await this.readSession(input.sessionAddress)
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

  // ── Admin actions ─────────────────────────────────────────

  async prepareAdminAction(input: AdminChallengeInput): Promise<AdminChallengeOutput> {
    const dwallet = toAddress(input.dwalletAddress)
    const decoded = await this.readPolicyOrThrow(dwallet, input.initAuthorityHash)
    const challenge = computeAdminChallenge(
      input.action,
      addressBytes(input.dwalletAddress),
      decoded.nextAdminNonce,
      decoded.primarySlot.raw,
    )
    return { challenge, expectedNonce: decoded.nextAdminNonce }
  }

  async submitAdminAction(input: AdminSubmitInput): Promise<TxResult> {
    const programId = this.requireProgramId()
    const dwallet = toAddress(input.dwalletAddress)
    const payer = getGasSponsorAddress()
    const decoded = await this.readPolicyOrThrow(dwallet, input.initAuthorityHash)
    if (decoded.nextAdminNonce !== input.expectedNonce) {
      throw new Error(
        `Admin nonce mismatch: expected ${decoded.nextAdminNonce}, got ${input.expectedNonce}`,
      )
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
    const baseAccounts = {
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

  async applyPendingChange(input: {
    dwalletAddress: Address
    initAuthorityHash: Uint8Array
  }): Promise<TxResult> {
    const programId = this.requireProgramId()
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
}

// ── Admin helpers ──────────────────────────────────────────────

function computeAdminChallenge(
  action: AdminAction,
  dwallet: Uint8Array,
  nonce: bigint,
  primarySlot: Uint8Array,
): Uint8Array {
  switch (action.type) {
    case 'add_member':
      return adminAddMemberChallenge({
        dwallet,
        newMemberSlot: memberSlotToCanonical(action.member),
        nonce,
        primarySlot,
      })
    case 'remove_member':
      return adminRemoveMemberChallenge({
        dwallet,
        memberSlotToRemove: memberSlotToCanonical(action.member),
        nonce,
        primarySlot,
      })
    case 'add_destination':
      return adminAddDestinationChallenge({
        dwallet,
        destination: action.destination,
        nonce,
        primarySlot,
      })
    case 'remove_destination':
      return adminRemoveDestinationChallenge({
        dwallet,
        destination: action.destination,
        nonce,
        primarySlot,
      })
    case 'revoke':
      return adminRevokeChallenge({ dwallet, nonce, primarySlot })
    case 'set_primary':
      return adminSetPrimaryChallenge({
        dwallet,
        newPrimarySlot: memberSlotToCanonical(action.newPrimary),
        nonce,
        currentPrimarySlot: primarySlot,
      })
    case 'set_quorum_threshold_immediate':
      return adminSetQuorumThresholdImmediateChallenge({
        dwallet,
        newThreshold: action.newThreshold,
        nonce,
        primarySlot,
      })
    case 'set_daily_limit_immediate':
      return adminSetDailyLimitImmediateChallenge({
        dwallet,
        newSome: action.newSome,
        newLimit: action.newLimit,
        nonce,
        primarySlot,
      })
    case 'set_cooldown_immediate':
      return adminSetCooldownImmediateChallenge({
        dwallet,
        newCooldownSeconds: action.newCooldownSeconds,
        nonce,
        primarySlot,
      })
    case 'propose_quorum_threshold_change':
      return adminProposeQuorumThresholdChallenge({
        dwallet,
        newThreshold: action.newThreshold,
        nonce,
        primarySlot,
      })
    case 'propose_daily_limit_change':
      return adminProposeDailyLimitChallenge({
        dwallet,
        newSome: action.newSome,
        newLimit: action.newLimit,
        nonce,
        primarySlot,
      })
    case 'propose_cooldown_change':
      return adminProposeCooldownChallenge({
        dwallet,
        newCooldownSeconds: action.newCooldownSeconds,
        nonce,
        primarySlot,
      })
  }
}

interface AdminBaseAccounts {
  programId: Address
  policyPda: Address
  dwallet: Address
  payer: Address
  /** Audit C2 (Opção 4): forwarded to every admin instruction encoder. */
  initAuthorityHash: Uint8Array
}

function buildAdminMainInstruction(
  action: AdminAction,
  base: AdminBaseAccounts,
  expectedNonce: bigint,
): Instruction {
  switch (action.type) {
    case 'add_member':
      return buildAddMemberInstruction({
        ...base,
        newMemberSlot: memberSlotToCanonical(action.member),
        expectedNonce,
      })
    case 'remove_member':
      return buildRemoveMemberInstruction({
        ...base,
        memberSlotToRemove: memberSlotToCanonical(action.member),
        expectedNonce,
      })
    case 'add_destination':
      return buildAddDestinationInstruction({
        ...base,
        destination: action.destination,
        expectedNonce,
      })
    case 'remove_destination':
      return buildRemoveDestinationInstruction({
        ...base,
        destination: action.destination,
        expectedNonce,
      })
    case 'revoke':
      return buildRevokeInstruction({ ...base, expectedNonce })
    case 'set_primary':
      return buildSetPrimaryInstruction({
        ...base,
        newPrimarySlot: memberSlotToCanonical(action.newPrimary),
        expectedNonce,
      })
    case 'set_quorum_threshold_immediate':
      return buildSetQuorumThresholdImmediateInstruction({
        ...base,
        newThreshold: action.newThreshold,
        expectedNonce,
      })
    case 'set_daily_limit_immediate':
      return buildSetDailyLimitImmediateInstruction({
        ...base,
        newSome: action.newSome,
        newLimit: action.newLimit,
        expectedNonce,
      })
    case 'set_cooldown_immediate':
      return buildSetCooldownImmediateInstruction({
        ...base,
        newCooldownSeconds: action.newCooldownSeconds,
        expectedNonce,
      })
    case 'propose_quorum_threshold_change':
      return buildProposeQuorumThresholdChangeInstruction({
        ...base,
        newThreshold: action.newThreshold,
        expectedNonce,
      })
    case 'propose_daily_limit_change':
      return buildProposeDailyLimitChangeInstruction({
        ...base,
        newSome: action.newSome,
        newLimit: action.newLimit,
        expectedNonce,
      })
    case 'propose_cooldown_change':
      return buildProposeCooldownChangeInstruction({
        ...base,
        newCooldownSeconds: action.newCooldownSeconds,
        expectedNonce,
      })
  }
}

// ── Singleton wiring ───────────────────────────────────────────

let adapter: PolicyAdapter | null = null

export function initSolanaAdapter(opts: SolanaAdapterOptions): PolicyAdapter {
  adapter = new SolanaAdapter(opts)
  return adapter
}

export function getPolicyAdapter(): PolicyAdapter {
  if (!adapter) throw new Error('Policy adapter not initialized')
  return adapter
}
