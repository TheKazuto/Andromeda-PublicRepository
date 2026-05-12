import { z } from 'zod'
import bs58 from 'bs58'
import { generateNonce, buildCanonicalMessage } from '../message.js'
import { isKnownScheme, getVerifier } from '../verifiers/index.js'
import { insertChallenge, consumeChallenge, findManagedDwalletsByPrimaryOwner } from '../store.js'
import { SCHEME_ED25519, SCHEME_SECP256K1 } from '../../clients/rulesPolicy/index.js'
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
  /**
   * Optional: the Solana address of a specific dWallet to confirm against the
   * proven wallet. Use this for external/bare dWallets that Andromeda did not
   * create (the managed-dWallet index can only auto-enumerate those it owns).
   */
  dwalletAddress: z.string().min(32).max(120).optional(),
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
  /** dWallets associated with the proven wallet (managed-index matches + any confirmed `dwalletAddress`). */
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

/**
 * Best-effort decode of a wallet address string into raw bytes, used only to
 * key the managed-dWallet index. Recognises:
 *   - hex (`0x`-prefixed or bare) → e.g. EVM 20-byte address, NEAR/Aptos
 *     32-byte implicit account / pubkey hex
 *   - base58 → e.g. Solana 32-byte pubkey
 * Returns `null` for formats that don't map cleanly to an on-chain identifier
 * (Cosmos bech32, Bitcoin base58/bech32, Substrate SS58, named NEAR accounts);
 * those need an explicit `dwalletAddress` instead.
 */
function decodeWalletAddressBytes(walletAddress: string): Uint8Array | null {
  const v = walletAddress.trim()
  const hexBody = v.startsWith('0x') || v.startsWith('0X') ? v.slice(2) : v
  if (/^[0-9a-fA-F]+$/.test(hexBody) && hexBody.length % 2 === 0 && hexBody.length > 0) {
    return new Uint8Array(Buffer.from(hexBody, 'hex'))
  }
  try {
    const decoded = bs58.decode(v)
    if (decoded.length > 0) return decoded
  } catch {
    /* not base58 */
  }
  return null
}

/**
 * Map decoded address bytes to the canonical on-chain primary owner
 * `(scheme, identifier)` pair that `rules-policy` would store:
 *   - 32 bytes → Ed25519 pubkey (Solana / NEAR / Aptos / …)
 *   - 20 bytes → Secp256k1 eth-style address (EVM / Bitcoin / Cosmos secp256k1 …)
 * Any other length has no canonical mapping.
 */
function onChainPrimaryFor(bytes: Uint8Array): { scheme: number; identifier: Uint8Array } | null {
  if (bytes.length === 32) return { scheme: SCHEME_ED25519, identifier: bytes }
  if (bytes.length === 20) return { scheme: SCHEME_SECP256K1, identifier: bytes }
  return null
}

function isLikelySolanaAddress(value: string): boolean {
  try {
    return bs58.decode(value.trim()).length === 32
  } catch {
    return false
  }
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

  const warnings: string[] = []
  const found = new Set<string>()

  // 1) Enumerate Andromeda-managed dWallets whose policy primary owner is the
  //    proven wallet. Skips silently when the address format can't be mapped.
  const decoded = decodeWalletAddressBytes(challenge.wallet_address)
  const onChainPrimary = decoded ? onChainPrimaryFor(decoded) : null
  if (onChainPrimary) {
    const managed = await findManagedDwalletsByPrimaryOwner({
      primaryScheme: onChainPrimary.scheme,
      primaryIdentifier: onChainPrimary.identifier,
    })
    for (const d of managed) found.add(d)
  } else {
    warnings.push(
      `discovery: this wallet's address format (scheme ${challenge.scheme}) is not auto-mappable to the managed-dWallet index; pass dwalletAddress explicitly to confirm a specific dWallet`,
    )
  }

  // 2) Confirm an explicitly supplied dWallet address (external / bare wallets).
  if (input.dwalletAddress) {
    if (!isLikelySolanaAddress(input.dwalletAddress)) {
      throw new Error('Invalid dwalletAddress')
    }
    if (!found.has(input.dwalletAddress)) {
      found.add(input.dwalletAddress)
      warnings.push(
        'discovery: dwalletAddress was supplied by the caller; ownership of the wallet is proven, but membership in that dWallet\'s policy is enforced on-chain at recovery time, not here',
      )
    }
  }

  if (found.size === 0) {
    warnings.push(
      'discovery: no Andromeda-managed dWallet found for this wallet; if recovering an external or bare dWallet, resubmit with dwalletAddress set to its Solana address',
    )
  }

  return {
    walletAddress: challenge.wallet_address,
    scheme: challenge.scheme,
    appId: challenge.app_id,
    dwallets: [...found],
    warnings,
    recoveredAt: new Date().toISOString(),
    readOnlyDisclaimer:
      'Discovery proves ownership only. Signing requires the appropriate access path (primary or quorum recovery).',
  }
}
