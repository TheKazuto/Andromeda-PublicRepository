// The 32-byte on-chain `MessageApproval.message_digest` for `preprocessed`.
//
// The Ika MessageApproval is keyed by `keccak256(message)` (skill §6.2, and the
// canonical `chains/solana/examples/voting/` e2e). The scheme's own hash
// (keccak/sha256/sha512/…) is what the Ika *network* applies to the message at
// *sign* time to produce the final signature — a separate step, not the approval
// key. The voting e2e signs Curve25519 (EddsaSha512) yet stores
// `keccak256(message)` in the approval and passes the RAW message to Sign; the
// network applies Ed25519/SHA-512 itself.
//
// EcdsaKeccak256 (EVM) coincides (keccak == keccak), so it was already correct.
// EdDSA (scheme 5 — Curve25519: Solana/Sui/…) previously returned `null`, which
// blocked request-signature for those chains; it now returns `keccak256` to
// match the approval model and the voting e2e, unblocking the sign flow.

import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { SignatureScheme } from '../engine/ika-client/bcs.js'

/**
 * The 32-byte `MessageApproval.message_digest` the network looks up for a sign
 * over `preprocessed`, or `null` for schemes whose approval digest is not yet
 * wired. The MessageApproval key is `keccak256(message)`; EdDSA returns that too
 * (the SHA-512 of Ed25519 is applied by the network at sign, not here).
 */
export function schemeDigest(scheme: number, preprocessed: Uint8Array): Uint8Array | null {
  switch (scheme) {
    case SignatureScheme.EcdsaKeccak256:
      return keccak_256(preprocessed)
    case SignatureScheme.EddsaSha512:
      // Curve25519 (Solana/Sui/…): approval digest is keccak256(message); the
      // network applies Ed25519/SHA-512 at sign time. Mirrors the voting e2e.
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
