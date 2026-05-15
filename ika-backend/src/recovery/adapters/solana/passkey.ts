/**
 * Passkey-primary session (`scheme = 3 = WebAuthn` — D1 Opção A) Solana flow.
 *
 * Builds, signs (gas sponsor = fee payer) and submits the on-chain
 * transactions for the passkey-primary recovery flow (Keyspring Fase 2):
 *
 *   open   → `[Secp256r1 precompile (credential_pubkey, open_challenge,
 *              authData || sha256(clientDataJSON))] + passkey_session_open`
 *   use    → `[Ed25519 precompile (eph_pk, use_challenge)]
 *              + recover_as_primary_passkey_session`
 *   close  → `passkey_session_close`
 *
 * The user never signs a Solana transaction. They authorize each session via
 * a WebAuthn assertion on `passkey_session_open_challenge` (one-shot, made by
 * the authenticator's secure element), and each per-session use via an
 * Ed25519 signature on `passkey_primary_use_challenge` with the ephemeral key
 * committed at open time. The on-chain `rules-policy` is the only authority.
 *
 * Solana-specific — not part of the chain-agnostic `PolicyAdapter` interface.
 */

import { address as toAddress, type Address } from '@solana/kit'

import { logger } from '../../../logger.js'
import { getSolanaRpc } from '../../../engine/solana-rpc.js'
import {
  buildEd25519PrecompileInstruction,
  buildSecp256r1PrecompileInstruction,
} from '../../../engine/precompiles.js'
import { getGasSponsorAddress, signAndSendInstructions } from '../../../engine/gas-sponsor.js'
import {
  buildPasskeyPrimarySlot,
  buildPasskeySessionCloseInstruction,
  buildPasskeySessionOpenInstruction,
  buildRecoverAsPrimaryPasskeySessionInstruction,
  decodePasskeySessionAccount,
  findCpiAuthorityPda,
  findEventAuthorityPda,
  findMessageApprovalPdaHierarchical,
  findPasskeySessionPda,
  findRulesPolicyPda,
  SCHEME_WEBAUTHN,
  type PasskeySessionAccountData,
} from '../../../clients/rulesPolicy/index.js'
import { passkeyPrimaryUseChallenge, passkeySessionOpenChallenge } from '../../challenge.js'
import type { ClearSigning } from '../../clear_signing.js'
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

export async function fetchPasskeySession(sessionAddress: Address): Promise<PasskeySessionAccountData> {
  const bytes = await readAccountBytes(sessionAddress)
  if (!bytes || bytes.length === 0) throw new Error('Passkey session not found on-chain')
  return decodePasskeySessionAccount(bytes)
}

// ── helpers ────────────────────────────────────────────────────

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0
}

/**
 * Off-chain mirror of the on-chain C3 anchor check: `clientDataJSON` must
 * contain `"challenge":"<b64url-no-pad challenge>"` exactly (43-char field
 * for a 32-byte challenge). Fail fast here so the gas sponsor doesn't waste
 * a tx that the program would reject anyway.
 */
function assertWebauthnChallengeAnchor(challenge: Uint8Array, clientDataJson: Uint8Array): void {
  if (challenge.length !== 32) {
    throw new Error(`webauthn challenge must be 32 bytes (got ${challenge.length})`)
  }
  const b64 = Buffer.from(challenge)
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
  const needle = `"challenge":"${b64}"`
  const cdjStr = Buffer.from(clientDataJson).toString('utf8')
  if (!cdjStr.includes(needle)) {
    throw new Error('clientDataJSON does not anchor the canonical challenge (audit C3)')
  }
}

function assertPasskeyPrimary(policyPrimarySlotRaw: Uint8Array, credentialPubkey: Uint8Array): Uint8Array {
  if (policyPrimarySlotRaw[0] !== SCHEME_WEBAUTHN) {
    throw new Error(`policy primary is not WebAuthn (scheme=${policyPrimarySlotRaw[0]})`)
  }
  const expected = buildPasskeyPrimarySlot(credentialPubkey)
  if (!eq(policyPrimarySlotRaw, expected)) {
    throw new Error('policy primary credential_pubkey does not match the given credential')
  }
  return expected
}

// ── flow inputs / outputs ──────────────────────────────────────

export interface PasskeyOpenPrepareInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  /** 33-byte compressed Secp256r1 pubkey of the passkey credential (must match the policy's primary slot). */
  credentialPubkey: Uint8Array
  /** `sha256(credentialId)` — pinned into the session at open (D12). */
  credentialIdHash: Uint8Array
  /** Ephemeral Ed25519 public key for per-use authorization. */
  ephPk: Uint8Array
  /** Maximum session lifetime requested by the client (capped on-chain by `SESSION_TTL_SECONDS`). */
  notAfterUnixTs: bigint
}

export interface PasskeyOpenPrepareOutput {
  challenge: Uint8Array
  humanMessage: string
  clearSigning: ClearSigning
  expectedSessionNonce: bigint
  sessionAddress: Address
}

export interface PasskeyOpenSubmitInput extends PasskeyOpenPrepareInput {
  /** WebAuthn `authenticatorData` (≤ 192 bytes — D13). */
  webauthnAuthData: Uint8Array
  /** WebAuthn `clientDataJSON` (≤ 192 bytes — contains the canonical challenge anchor). */
  webauthnClientDataJson: Uint8Array
  /** 64-byte raw Secp256r1 signature `r||s` produced by the authenticator over `authData || sha256(clientDataJSON)`. */
  webauthnSignature: Uint8Array
  expectedSessionNonce: bigint
}

export interface PasskeyOpenSubmitResult {
  txSignature: string
  sessionAddress: Address
}

export interface PasskeyUsePrepareInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  sessionAddress: string
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
}

export interface PasskeyUsePrepareOutput {
  challenge: Uint8Array
  humanMessage: string
  clearSigning: ClearSigning
  expectedUseNonce: bigint
  /** Session expiry, unix seconds. */
  sessionExpiresAt: number
}

export interface PasskeyUseSubmitInput extends PasskeyUsePrepareInput {
  /** Off-chain Ed25519 signature of `passkey_primary_use_challenge` by the session's ephemeral key. */
  ephSignature: Uint8Array
  expectedUseNonce: bigint
}

export interface PasskeyUseSubmitResult {
  txSignature: string
  messageApprovalAddress: Address
}

export interface PasskeyCloseInput {
  dwalletAddress: string
  initAuthorityHash: Uint8Array
  sessionAddress: string
}

export interface PasskeyTxResult {
  txSignature: string
}

// ── open ───────────────────────────────────────────────────────

export async function preparePasskeySessionOpen(
  ctx: SolanaCtx,
  input: PasskeyOpenPrepareInput,
): Promise<PasskeyOpenPrepareOutput> {
  if (input.credentialPubkey.length !== 33) {
    throw new Error(`credential_pubkey must be 33 bytes (got ${input.credentialPubkey.length})`)
  }
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  const primarySlot = assertPasskeyPrimary(decoded.primarySlot.raw, input.credentialPubkey)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const sessionPda = await findPasskeySessionPda(
    ctx.programId,
    policyPda.address,
    dwallet,
    decoded.nextPasskeySessionNonce,
  )
  const result = passkeySessionOpenChallenge({
    dwallet: addressBytes(dwallet),
    primarySlot,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    credentialIdHash: input.credentialIdHash,
    sessionNonce: decoded.nextPasskeySessionNonce,
  })
  return {
    challenge: result.hash,
    humanMessage: result.humanMessage,
    clearSigning: result.clearSigning,
    expectedSessionNonce: decoded.nextPasskeySessionNonce,
    sessionAddress: sessionPda.address,
  }
}

export async function submitPasskeySessionOpen(
  ctx: SolanaCtx,
  input: PasskeyOpenSubmitInput,
): Promise<PasskeyOpenSubmitResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const decoded = await fetchPolicyAccount(ctx, dwallet, input.initAuthorityHash)
  if (decoded.nextPasskeySessionNonce !== input.expectedSessionNonce) {
    throw new Error(
      `Passkey session nonce mismatch: expected ${decoded.nextPasskeySessionNonce}, got ${input.expectedSessionNonce}`,
    )
  }
  const primarySlot = assertPasskeyPrimary(decoded.primarySlot.raw, input.credentialPubkey)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const sessionPda = await findPasskeySessionPda(
    ctx.programId,
    policyPda.address,
    dwallet,
    input.expectedSessionNonce,
  )
  const eventAuthorityPda = await findEventAuthorityPda(ctx.programId)
  const { hash: challenge } = passkeySessionOpenChallenge({
    dwallet: addressBytes(dwallet),
    primarySlot,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    credentialIdHash: input.credentialIdHash,
    sessionNonce: input.expectedSessionNonce,
  })
  // WebAuthn: the authenticator signs `authData || sha256(clientDataJSON)`.
  // The on-chain `verify_signature` for SCHEME_WEBAUTHN reconstructs that
  // message and looks up the Secp256r1 precompile invocation that signed it,
  // plus parses `clientDataJSON` to bind `challenge` (audit C3 anchor).
  // Defense in depth: validate the binding off-chain before spending gas.
  assertWebauthnChallengeAnchor(challenge, input.webauthnClientDataJson)
  const webauthnSignedMessage = new Uint8Array(
    input.webauthnAuthData.length + 32,
  )
  webauthnSignedMessage.set(input.webauthnAuthData, 0)
  webauthnSignedMessage.set(sha256(input.webauthnClientDataJson), input.webauthnAuthData.length)
  const precompileIx = buildSecp256r1PrecompileInstruction({
    publicKey: input.credentialPubkey,
    message: webauthnSignedMessage,
    signature: input.webauthnSignature,
  })
  const mainIx = buildPasskeySessionOpenInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: sessionPda.address,
    payer: getGasSponsorAddress(),
    eventAuthorityPda: eventAuthorityPda.address,
    initAuthorityHash: input.initAuthorityHash,
    ephPk: input.ephPk,
    notAfterUnixTs: input.notAfterUnixTs,
    credentialIdHash: input.credentialIdHash,
    expectedSessionNonce: input.expectedSessionNonce,
    webauthnAuthData: input.webauthnAuthData,
    webauthnClientDataJson: input.webauthnClientDataJson,
  })
  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.passkey.open', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info({ dwallet: input.dwalletAddress, txSignature: sig }, 'passkey: session opened')
  return { txSignature: sig, sessionAddress: sessionPda.address }
}

// ── use ────────────────────────────────────────────────────────

export async function preparePasskeyUse(
  ctx: SolanaCtx,
  input: PasskeyUsePrepareInput,
): Promise<PasskeyUsePrepareOutput> {
  const session = await fetchPasskeySession(toAddress(input.sessionAddress))
  const sessionDwallet = addrDecoder.decode(session.dwallet) as Address
  if (sessionDwallet !== toAddress(input.dwalletAddress)) {
    throw new Error('Passkey session does not belong to the given dWallet')
  }
  const expiresAt = Number(session.expiresAt)
  if (Math.floor(Date.now() / 1000) >= expiresAt) throw new Error('Passkey session expired')
  const primarySlot = buildPasskeyPrimarySlot(session.credentialPubkey)
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId: ctx.ikaProgramId,
    dwallet: toAddress(input.dwalletAddress),
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })
  const result = passkeyPrimaryUseChallenge({
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
  return {
    challenge: result.hash,
    humanMessage: result.humanMessage,
    clearSigning: result.clearSigning,
    expectedUseNonce: session.nextUseNonce,
    sessionExpiresAt: expiresAt,
  }
}

export async function submitPasskeyUse(
  ctx: SolanaCtx,
  input: PasskeyUseSubmitInput,
): Promise<PasskeyUseSubmitResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const session = await fetchPasskeySession(toAddress(input.sessionAddress))
  const sessionDwallet = addrDecoder.decode(session.dwallet) as Address
  if (sessionDwallet !== dwallet) throw new Error('Passkey session does not belong to the given dWallet')
  if (session.nextUseNonce !== input.expectedUseNonce) {
    throw new Error(
      `Passkey use nonce mismatch: expected ${session.nextUseNonce}, got ${input.expectedUseNonce}`,
    )
  }
  if (Math.floor(Date.now() / 1000) >= Number(session.expiresAt)) throw new Error('Passkey session expired')

  const primarySlot = buildPasskeyPrimarySlot(session.credentialPubkey)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const cpiAuthorityPda = await findCpiAuthorityPda(ctx.programId)
  const eventAuthorityPda = await findEventAuthorityPda(ctx.programId)
  const messageApproval = await findMessageApprovalPdaHierarchical({
    ikaProgramId: ctx.ikaProgramId,
    dwallet,
    signatureScheme: input.signatureScheme,
    messageDigest: input.messageDigest,
    metadataDigest: input.metadataDigest,
  })
  const { hash: challenge } = passkeyPrimaryUseChallenge({
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
  const precompileIx = buildEd25519PrecompileInstruction({
    publicKey: session.ephPk,
    message: challenge,
    signature: input.ephSignature,
  })
  const mainIx = buildRecoverAsPrimaryPasskeySessionInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: toAddress(input.sessionAddress),
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
  const sig = await signAndSendInstructions([precompileIx, mainIx], 'recovery.passkey.use', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  logger.info({ dwallet: input.dwalletAddress, txSignature: sig }, 'passkey: signature authorized')
  return { txSignature: sig, messageApprovalAddress: messageApproval.address }
}

// ── close ──────────────────────────────────────────────────────

export async function submitPasskeySessionClose(
  ctx: SolanaCtx,
  input: PasskeyCloseInput,
): Promise<PasskeyTxResult> {
  const dwallet = toAddress(input.dwalletAddress)
  const policyPda = await findRulesPolicyPda(ctx.programId, dwallet, input.initAuthorityHash)
  const ix = buildPasskeySessionCloseInstruction({
    programId: ctx.programId,
    policyPda: policyPda.address,
    dwallet,
    sessionPda: toAddress(input.sessionAddress),
    rentDestination: getGasSponsorAddress(),
    initAuthorityHash: input.initAuthorityHash,
  })
  const sig = await signAndSendInstructions([ix], 'recovery.passkey.close', {
    dwalletAddress: input.dwalletAddress,
    policyAddress: policyPda.address,
  })
  return { txSignature: sig }
}
