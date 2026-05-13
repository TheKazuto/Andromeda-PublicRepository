/**
 * Login Social (`scheme = 4 = OidcJwt`) — Solana recovery flow module.
 *
 * Builds, signs (gas sponsor = fee payer) and submits the on-chain
 * transactions for the OIDC-primary recovery flow:
 *
 *   stage   → `oidc_jwt_stage`
 *   open    → `[Ed25519 precompile (eph_pk, open_challenge)] + oidc_session_open`
 *   use     → `[Ed25519 precompile (eph_pk, use_challenge)]  + recover_as_primary_oidc_session`
 *   close   → `oidc_session_close`
 *   staging → `oidc_jwt_staging_close`
 *
 * The user never signs a Solana transaction — they only sign the 32-byte
 * `oidc-session-open` / `oidc-primary-use` challenges off-chain with their
 * ephemeral Ed25519 key (held on their device). The on-chain `rules-policy`
 * (`scheme = 4`) + `oidc-verifier` + `jwk-registry` are the source of truth;
 * the JWT verification done in the routes (`jose` JWKS) is a pre-check.
 *
 * Solana-specific — not part of the chain-agnostic `PolicyAdapter` interface.
 */

import { address as toAddress, type Address } from '@solana/kit'

import { logger } from '../../../logger.js'
import { getSolanaRpc } from '../../../engine/solana-rpc.js'
import { buildEd25519PrecompileInstruction } from '../../../engine/precompiles.js'
import { getGasSponsorAddress, signAndSendInstructions } from '../../../engine/gas-sponsor.js'
import {
  buildOidcJwtStageInstruction,
  buildOidcJwtStagingCloseInstruction,
  buildOidcSessionCloseInstruction,
  buildOidcSessionOpenInstruction,
  buildRecoverAsPrimaryOidcSessionInstruction,
  decodeOidcJwtStagingAccount,
  decodeOidcSessionAccount,
  findCpiAuthorityPda,
  findEventAuthorityPda,
  findJwkRegistryPda,
  findMessageApprovalPdaHierarchical,
  findOidcJwtStagingPda,
  findOidcSessionPda,
  findRulesPolicyPda,
  type OidcSessionAccountData,
} from '../../../clients/rulesPolicy/index.js'
import { oidcPrimaryUseChallenge, oidcSessionOpenChallenge } from '../../challenge.js'
import { oidcPrimarySlotBytes } from '../../../oidc/derive.js'
import { addrDecoder, addressBytes, sha256, type SolanaCtx } from './internal.js'
import { fetchPolicyAccount } from './state.js'

// ── small on-chain reads ───────────────────────────────────────

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

/** Read + decode an `OidcJwtStaging` account; throws if absent / undecodable. */
export async function fetchOidcStaging(
  stagingAddress: Address,
): Promise<ReturnType<typeof decodeOidcJwtStagingAccount>> {
  const bytes = await readAccountBytes(stagingAddress)
  if (!bytes || bytes.length === 0) throw new Error('OIDC staging account not found on-chain')
  return decodeOidcJwtStagingAccount(bytes)
}

/** Read + decode an `OidcSession` account; throws if absent / undecodable. */
export async function fetchOidcSession(sessionAddress: Address): Promise<OidcSessionAccountData> {
  const bytes = await readAccountBytes(sessionAddress)
  if (!bytes || bytes.length === 0) throw new Error('OIDC session not found on-chain')
  return decodeOidcSessionAccount(bytes)
}

// ── helpers ────────────────────────────────────────────────────

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0
}

/** `sha256(header.payload)` — the JWS signing input — from the compact JWT bytes. */
export function jwsSigningInputDigest(jwtBytes: Uint8Array): Uint8Array {
  // ASCII '.' = 0x2e — the digest covers everything before the SECOND dot.
  let first = -1
  let second = -1
  for (let i = 0; i < jwtBytes.length; i += 1) {
    if (jwtBytes[i] === 0x2e) {
      if (first === -1) first = i
      else {
        second = i
        break
      }
    }
  }
  if (first === -1 || second === -1) throw new Error('malformed JWT: expected two `.` separators')
  return sha256(jwtBytes.subarray(0, second))
}

/** Verify the configured `JwkRegistry` address is the canonical PDA; return `{address, bump}`. */
async function resolveCanonicalJwkRegistry(ctx: SolanaCtx): Promise<{ address: Address; bump: number }> {
  const { address, bump } = await findJwkRegistryPda()
  if (address !== ctx.oidcJwkRegistry()) {
    throw new Error('configured JwkRegistry address is not the canonical PDA')
  }
  return { address, bump }
}

function assertOidcPrimary(policyPrimarySlotRaw: Uint8Array, addrSeed: Uint8Array): Uint8Array {
  const expected = oidcPrimarySlotBytes(addrSeed)
  if (!eq(policyPrimarySlotRaw, expected)) {
    throw new Error('policy primary is not [4, addr_seed, 0] for this OIDC identity')
  }
  return expected
}

// ── flow inputs / outputs ──────────────────────────────────────

export interface OidcStageInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  /** The compact JWT (`header.payload.signature`) bytes — already validated by the route. */
  jwtBytes: Uint8Array
}
export interface OidcStageResult {
  txSignature: string
  stagingAddress: Address
  stagingNonce: bigint
}

export interface OidcOpenPrepareInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  ephPk: Uint8Array
  notAfterUnixTs: bigint
  /** SHA-256 of the JWS signing input (`header.payload`) of the staged JWT. */
  jwtDigest: Uint8Array
  /** `sha256("andromeda::oidc::addr::v1" || ...)` derived from the verified claims. */
  addrSeed: Uint8Array
}
export interface OidcOpenPrepareOutput {
  challenge: Uint8Array
  expectedSessionNonce: bigint
  sessionAddress: Address
  jwkRegistryAddress: Address
  jwkRegistryBump: number
  oidcVerifierVersion: number
}

export interface OidcOpenSubmitInput extends OidcOpenPrepareInput {
  stagingAddress: string
  nonceRandomness: Uint8Array
  /** Off-chain Ed25519 signature of the `oidc-session-open` challenge by the ephemeral key. */
  ephSignature: Uint8Array
  expectedSessionNonce: bigint
  issuerHash: Uint8Array
  audienceHash: Uint8Array
  kidHash: Uint8Array
}
export interface OidcOpenSubmitResult {
  txSignature: string
  sessionAddress: Address
}

export interface OidcUsePrepareInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  sessionAddress: string
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
}
export interface OidcUsePrepareOutput {
  challenge: Uint8Array
  expectedUseNonce: bigint
  /** Session expiry, unix seconds. */
  sessionExpiresAt: number
}

export interface OidcUseSubmitInput extends OidcUsePrepareInput {
  userPubkey: Uint8Array
  /** Curve of the dWallet (passed to Ika `approve_message`). */
  signatureScheme: number
  /** Off-chain Ed25519 signature of the `oidc-primary-use` challenge by the ephemeral key. */
  ephSignature: Uint8Array
  expectedUseNonce: bigint
}
export interface OidcUseSubmitResult {
  txSignature: string
  messageApprovalAddress: Address
}

export interface OidcCloseInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  sessionAddress: string
}
export interface OidcStagingCloseInput {
  stagingAddress: string
}
export interface OidcTxResult {
  txSignature: string
}

// ── stage ──────────────────────────────────────────────────────

export async function submitOidcJwtStage(ctx: SolanaCtx, input: OidcStageInput): Promise<OidcStageResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const payer = getGasSponsorAddress()
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const stagingPda = await findOidcJwtStagingPda(
    ctx.programId,
    policyPda.address,
    dwallet,
    decoded.nextStagingNonce,
  )
  const ix = buildOidcJwtStageInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    stagingPda: stagingPda.address,
    payer,
    initAuthorityHash: input.initAuthorityHash,
    jwt: input.jwtBytes,
  })
  const sig = await signAndSendInstructions([ix], 'recovery.oidc.stage', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info({ dwallet: input.dwalletAddress, txSignature: sig }, 'oidc: jwt staged')
  return { txSignature: sig, stagingAddress: stagingPda.address, stagingNonce: decoded.nextStagingNonce }
}

// ── open ───────────────────────────────────────────────────────

export async function prepareOidcSessionOpen(
  ctx: SolanaCtx,
  input: OidcOpenPrepareInput,
): Promise<OidcOpenPrepareOutput> {
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  const primarySlot = assertOidcPrimary(decoded.primarySlot.raw, input.addrSeed)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const { address: jwkRegistry, bump: jwkRegistryBump } = await resolveCanonicalJwkRegistry(ctx)
  const challenge = oidcSessionOpenChallenge({
    dwallet: addressBytes(dwallet),
    primarySlot,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    jwtDigest: input.jwtDigest,
    jwkRegistry: addressBytes(jwkRegistry),
    oidcVerifierVersion: ctx.oidcVerifierVersion,
    sessionNonce: decoded.nextOidcSessionNonce,
  })
  const sessionPda = await findOidcSessionPda(
    ctx.programId,
    policyPda.address,
    dwallet,
    decoded.nextOidcSessionNonce,
  )
  return {
    challenge,
    expectedSessionNonce: decoded.nextOidcSessionNonce,
    sessionAddress: sessionPda.address,
    jwkRegistryAddress: jwkRegistry,
    jwkRegistryBump,
    oidcVerifierVersion: ctx.oidcVerifierVersion,
  }
}

export async function submitOidcSessionOpen(
  ctx: SolanaCtx,
  input: OidcOpenSubmitInput,
): Promise<OidcOpenSubmitResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  if (decoded.nextOidcSessionNonce !== input.expectedSessionNonce) {
    throw new Error(
      `OIDC session nonce mismatch: expected ${decoded.nextOidcSessionNonce}, got ${input.expectedSessionNonce}`,
    )
  }
  const primarySlot = assertOidcPrimary(decoded.primarySlot.raw, input.addrSeed)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const { address: jwkRegistry, bump: jwkRegistryBump } = await resolveCanonicalJwkRegistry(ctx)
  const sessionPda = await findOidcSessionPda(
    ctx.programId,
    policyPda.address,
    dwallet,
    input.expectedSessionNonce,
  )
  const eventAuthorityPda = await findEventAuthorityPda(ctx.programId)
  const challenge = oidcSessionOpenChallenge({
    dwallet: addressBytes(dwallet),
    primarySlot,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    jwtDigest: input.jwtDigest,
    jwkRegistry: addressBytes(jwkRegistry),
    oidcVerifierVersion: ctx.oidcVerifierVersion,
    sessionNonce: input.expectedSessionNonce,
  })
  const sponsor = getGasSponsorAddress()
  const precompileIx = buildEd25519PrecompileInstruction({
    publicKey: input.ephPk,
    message: challenge,
    signature: input.ephSignature,
  })
  const mainIx = buildOidcSessionOpenInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    stagingPda: toAddress(input.stagingAddress),
    jwkRegistry,
    sessionPda: sessionPda.address,
    stagingPayer: sponsor,
    payer: sponsor,
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthorityHash: input.initAuthorityHash,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    nonceRandomness: input.nonceRandomness,
    oidcVerifierVersion: ctx.oidcVerifierVersion,
    jwkRegistryBump,
    issuerHash: input.issuerHash,
    audienceHash: input.audienceHash,
    kidHash: input.kidHash,
    expectedSessionNonce: input.expectedSessionNonce,
  })
  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.oidc.open', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info({ dwallet: input.dwalletAddress, txSignature: sig }, 'oidc: session opened')
  return { txSignature: sig, sessionAddress: sessionPda.address }
}

// ── use ────────────────────────────────────────────────────────

export async function prepareOidcUse(ctx: SolanaCtx, input: OidcUsePrepareInput): Promise<OidcUsePrepareOutput> {
  const session = await fetchOidcSession(toAddress(input.sessionAddress))
  const sessionDwallet = addrDecoder.decode(session.dwallet) as Address
  if (sessionDwallet !== toAddress(input.dwalletAddress)) {
    throw new Error('OIDC session does not belong to the given dWallet')
  }
  const expiresAt = Number(session.expiresAt)
  if (Math.floor(Date.now() / 1000) >= expiresAt) throw new Error('OIDC session expired')
  const primarySlot = oidcPrimarySlotBytes(session.addrSeed)
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId: ctx.ikaProgramId,
    dwallet: toAddress(input.dwalletAddress),
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })
  const challenge = oidcPrimaryUseChallenge({
    session: addressBytes(input.sessionAddress),
    dwallet: addressBytes(input.dwalletAddress),
    messageApproval: addressBytes(messageApproval.address),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    useNonce: session.nextUseNonce,
    primarySlot,
  })
  return { challenge, expectedUseNonce: session.nextUseNonce, sessionExpiresAt: expiresAt }
}

export async function submitOidcUse(ctx: SolanaCtx, input: OidcUseSubmitInput): Promise<OidcUseSubmitResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const session = await fetchOidcSession(toAddress(input.sessionAddress))
  const sessionDwallet = addrDecoder.decode(session.dwallet) as Address
  if (sessionDwallet !== dwallet) throw new Error('OIDC session does not belong to the given dWallet')
  if (session.nextUseNonce !== input.expectedUseNonce) {
    throw new Error(`OIDC use nonce mismatch: expected ${session.nextUseNonce}, got ${input.expectedUseNonce}`)
  }
  if (Math.floor(Date.now() / 1000) >= Number(session.expiresAt)) throw new Error('OIDC session expired')

  const primarySlot = oidcPrimarySlotBytes(session.addrSeed)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const cpiAuthorityPda = await findCpiAuthorityPda(ctx.programId)
  const eventAuthorityPda = await findEventAuthorityPda(ctx.programId)
  // Hierarchical seeds — same form the recover_as_primary path uses on devnet.
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId: ctx.ikaProgramId,
    dwallet,
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })
  const challenge = oidcPrimaryUseChallenge({
    session: addressBytes(input.sessionAddress),
    dwallet: addressBytes(input.dwalletAddress),
    messageApproval: addressBytes(messageApproval.address),
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    useNonce: input.expectedUseNonce,
    primarySlot,
  })
  const jwkRegistry = addrDecoder.decode(session.jwkRegistry) as Address
  const precompileIx = buildEd25519PrecompileInstruction({
    publicKey: session.ephPk,
    message: challenge,
    signature: input.ephSignature,
  })
  const mainIx = buildRecoverAsPrimaryOidcSessionInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: toAddress(input.sessionAddress),
    jwkRegistry,
    coordinator: ctx.coordinator(),
    messageApproval: messageApproval.address,
    payer: getGasSponsorAddress(),
    cpiAuthorityPda: cpiAuthorityPda.address,
    ikaProgramId: ctx.ikaProgramId,
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthorityHash: input.initAuthorityHash,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
    userPubkey: input.userPubkey,
    signatureScheme: input.signatureScheme,
    messageApprovalBump: messageApproval.bump,
    cpiAuthorityBump: cpiAuthorityPda.bump,
    expectedUseNonce: input.expectedUseNonce,
  })
  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.oidc.use', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info({ dwallet: input.dwalletAddress, txSignature: sig }, 'oidc: signature authorized')
  return { txSignature: sig, messageApprovalAddress: messageApproval.address }
}

// ── close ──────────────────────────────────────────────────────

export async function submitOidcSessionClose(ctx: SolanaCtx, input: OidcCloseInput): Promise<OidcTxResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  // The session's `payer_for_close` is the gas sponsor (it funded the `open`).
  const ix = buildOidcSessionCloseInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: toAddress(input.sessionAddress),
    rentDestination: getGasSponsorAddress(),
    initAuthorityHash: input.initAuthorityHash,
  })
  const sig = await signAndSendInstructions([ix], 'recovery.oidc.close', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  return { txSignature: sig }
}

export async function submitOidcJwtStagingClose(
  ctx: SolanaCtx,
  input: OidcStagingCloseInput,
): Promise<OidcTxResult> {
  // The staging's `payer_for_close` is the gas sponsor (it funded the `stage`).
  const ix = buildOidcJwtStagingCloseInstruction({
    programId: ctx.programId,
    stagingPda: toAddress(input.stagingAddress),
    rentDestination: getGasSponsorAddress(),
  })
  const sig = await signAndSendInstructions([ix], 'recovery.oidc.stagingClose', {})
  return { txSignature: sig }
}
