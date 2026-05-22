// Scheme hash applied AFTER the chain envelope. This is the hash the Ika
// network applies to the message at sign time, and therefore the value that
// must land in the on-chain `MessageApproval.message_digest`.
//
// Defined only for the secp256k1 ECDSA schemes, where the destination digest is
// an unambiguous 32-byte pre-hash (and matches the production EVM flow). For the
// EdDSA scheme (5) the destination digest is not a simple 32-byte pre-hash of
// the message, so we return `null` rather than invent one — the caller (e.g.
// `/v1/dwallet/prepare-message`) surfaces `digestHex: null` for those chains.

import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { SignatureScheme } from '../engine/ika-client/bcs.js'

/**
 * The 32-byte digest the network derives from `preprocessed` for `scheme`, or
 * `null` when the scheme has no simple pre-hash digest (EdDSA / unsupported).
 */
export function schemeDigest(scheme: number, preprocessed: Uint8Array): Uint8Array | null {
  switch (scheme) {
    case SignatureScheme.EcdsaKeccak256:
      return keccak_256(preprocessed)
    case SignatureScheme.EcdsaSha256:
      return sha256(preprocessed)
    case SignatureScheme.EcdsaDoubleSha256:
      return sha256(sha256(preprocessed))
    case SignatureScheme.EcdsaBlake2b256:
      return blake2b(preprocessed, { dkLen: 32 })
    default:
      return null
  }
}
