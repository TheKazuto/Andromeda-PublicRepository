import { z } from 'zod'
import { generateNonce, buildCanonicalMessage } from '../message.js'
import { isKnownScheme, getVerifier } from '../verifiers/index.js'
import { insertChallenge, consumeChallenge } from '../store.js'
import type { AppConfig } from '../../config.js'

export const challengeRequestSchema = z.object({
  appId: z.string().min(1).max(120),
  walletAddress: z.string().min(1).max(120),
  scheme: z.string(),
})

export const resolveRequestSchema = z.object({
  nonce: z.string().min(1),
  signature: z.string().min(1),
  publicKey: z.string().optional(),
})

export interface ChallengeResult {
  nonce: string
  message: string
  expiresAt: string
}

export interface ResolveResult {
  walletAddress: string
  scheme: string
  appId: string
  dwallets: string[]
  warnings: string[]
  recoveredAt: string
  readOnlyDisclaimer: string
}

export async function buildChallenge(
  input: z.infer<typeof challengeRequestSchema>,
  config: AppConfig,
): Promise<ChallengeResult> {
  if (!isKnownScheme(input.scheme)) {
    throw new Error(`Invalid scheme: ${input.scheme}`)
  }
  if (!getVerifier(input.scheme)) {
    throw new Error(`Invalid scheme verifier not registered: ${input.scheme}`)
  }
  const nonce = generateNonce()
  const issuedAt = new Date()
  const expiresAt = new Date(issuedAt.getTime() + config.recovery.challengeTtlSeconds * 1000)
  const message = buildCanonicalMessage({
    appId: input.appId,
    walletAddress: input.walletAddress,
    scheme: input.scheme,
    nonce,
    issuedAtIso: issuedAt.toISOString(),
    expiresAtIso: expiresAt.toISOString(),
  })
  await insertChallenge({
    nonce,
    appId: input.appId,
    scheme: input.scheme,
    walletAddress: input.walletAddress,
    message,
    expiresAt,
  })
  return { nonce, message, expiresAt: expiresAt.toISOString() }
}

export async function resolveChallenge(
  input: z.infer<typeof resolveRequestSchema>,
): Promise<ResolveResult> {
  const challenge = await consumeChallenge(input.nonce)
  if (!challenge) {
    throw new Error('Recovery challenge expired')
  }
  const verifier = getVerifier(challenge.scheme)
  if (!verifier) {
    throw new Error(`Invalid scheme: ${challenge.scheme}`)
  }
  const verified = await verifier.verify({
    message: challenge.message,
    walletAddress: challenge.wallet_address,
    signature: input.signature,
    ...(input.publicKey ? { publicKey: input.publicKey } : {}),
  })
  if (!verified) {
    throw new Error('Invalid signature')
  }

  // TODO: query Solana for dWallets associated with `challenge.wallet_address`.
  // The Identity Layer derives a Solana-side wallet hint from the proven
  // wallet address; we then call into engine to list dWallets owned by it.
  // For now, return an empty list with a warning.
  const dwallets: string[] = []
  const warnings: string[] = ['discovery: dWallet enumeration pending engine wiring']

  return {
    walletAddress: challenge.wallet_address,
    scheme: challenge.scheme,
    appId: challenge.app_id,
    dwallets,
    warnings,
    recoveredAt: new Date().toISOString(),
    readOnlyDisclaimer:
      'Discovery proves ownership only. Signing requires the appropriate access path (primary or quorum recovery).',
  }
}
