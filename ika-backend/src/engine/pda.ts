import { sha256 } from '@noble/hashes/sha2.js'

/**
 * Helpers for deriving PDAs against the Ika dWallet program and downstream
 * programs (e.g., RulesPolicy).
 *
 * NOTE: For production, prefer `@solana/kit`'s `getProgramDerivedAddress`,
 * which handles the curve check + bump search natively. This module exists
 * to centralize the seed string constants.
 */

export const CPI_AUTHORITY_SEED = new TextEncoder().encode('__ika_cpi_authority')
export const DWALLET_SEED = new TextEncoder().encode('dwallet')
export const ATTESTATION_SEED = new TextEncoder().encode('attestation')
export const PUBLIC_USER_SHARE_SEED = new TextEncoder().encode('public_user_share')
export const ENCRYPTED_USER_SHARE_SEED = new TextEncoder().encode('encrypted_user_share')
export const PARTIAL_USER_SIG_SEED = new TextEncoder().encode('partial_user_sig')
export const MESSAGE_APPROVAL_SEED = new TextEncoder().encode('message_approval')
export const GAS_DEPOSIT_SEED = new TextEncoder().encode('gas_deposit')

const MAX_SEED_LEN = 32

/**
 * Chunks a buffer into ≤32-byte slices for use as PDA seeds.
 */
export function chunkBytes(input: Uint8Array): Uint8Array[] {
  const chunks: Uint8Array[] = []
  for (let i = 0; i < input.length; i += MAX_SEED_LEN) {
    chunks.push(input.slice(i, Math.min(i + MAX_SEED_LEN, input.length)))
  }
  return chunks
}

export function curveBytesLE(curveId: number): Uint8Array {
  return new Uint8Array([curveId & 0xff, (curveId >> 8) & 0xff])
}

export function dwalletSeeds(curveId: number, publicKey: Uint8Array): Uint8Array[] {
  const concat = new Uint8Array(2 + publicKey.length)
  concat.set(curveBytesLE(curveId), 0)
  concat.set(publicKey, 2)
  return [DWALLET_SEED, ...chunkBytes(concat)]
}

export function messageApprovalSeeds(dwalletPubkey: Uint8Array, messageHash: Uint8Array): Uint8Array[] {
  return [MESSAGE_APPROVAL_SEED, dwalletPubkey, messageHash]
}

export function gasDepositSeeds(userPubkey: Uint8Array): Uint8Array[] {
  return [GAS_DEPOSIT_SEED, userPubkey]
}

export function cpiAuthoritySeeds(): Uint8Array[] {
  return [CPI_AUTHORITY_SEED]
}

/**
 * Hash helper kept around for digest computation (Keccak-256 lives in @noble).
 */
export function sha256Hash(data: Uint8Array): Uint8Array {
  return sha256(data)
}
