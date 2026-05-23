// The 32-byte on-chain `MessageApproval.message_digest` for `preprocessed`.
//
// The Ika MessageApproval PDA is keyed by `keccak256(message)` for EVERY
// signature scheme. Confirmed against the Ika pre-alpha docs ("the
// message_digest must be the keccak256 hash of the message ... using any other
// hash function will result in a PDA mismatch") and the clear-msig reference
// (`chains/mod.rs::dispatch_sighash` returns `keccak256(preimage)` for all
// chains, Zcash included). The scheme's own hash (sha256 / double-sha256 /
// blake2b / blake2b-personalized / sha512) is what the Ika *network* applies to
// the RAW message at *sign* time to produce the final signature — a separate
// step, NOT the approval key.
//
// History (Update 6 M1-fix): EVM (scheme 0, keccak == keccak) was always
// correct; EdDSA (scheme 5) was fixed earlier to return keccak256 and validated
// by the voting e2e + a live Solana smoke. Schemes 1/2/4 (Cosmos, Avalanche,
// Bitcoin, Filecoin, VeChain — and now Zcash) previously returned the scheme's
// pre-hash, which is wrong for the approval key and fails at sign time with
// "MessageApproval PDA not found". They had never been signed live. This file
// now returns keccak256 for every supported scheme.
//
// Pre-alpha note: the final judge is the on-chain smoke per scheme; treat the
// 1/2/4 families as "fixed but not yet live-validated" until that smoke runs.

import { keccak_256 } from '@noble/hashes/sha3.js'
import { SignatureScheme } from '../engine/ika-client/bcs.js'

/**
 * The 32-byte `MessageApproval.message_digest` the network looks up for a sign
 * over `preprocessed`: `keccak256(preprocessed)` for every supported scheme, or
 * `null` for an unrecognized scheme id (defensive guard — never hit in the
 * normal flow, where the scheme comes from `resolveChainParams`).
 */
export function schemeDigest(scheme: number, preprocessed: Uint8Array): Uint8Array | null {
  switch (scheme) {
    case SignatureScheme.EcdsaKeccak256: // 0 — EVM, Tron
    case SignatureScheme.EcdsaSha256: // 1 — Cosmos, Avalanche
    case SignatureScheme.EcdsaDoubleSha256: // 2 — Bitcoin
    case SignatureScheme.TaprootSha256: // 3 — deferred (Schnorr presign)
    case SignatureScheme.EcdsaBlake2b256: // 4 — Filecoin, VeChain, Zcash
    case SignatureScheme.EddsaSha512: // 5 — Solana, Sui, …
    case SignatureScheme.SchnorrkelMerlin: // 6 — deferred (sr25519)
      // Approval key is keccak256 of the raw (preprocessed) message for ALL
      // schemes; the network applies the scheme hash at sign time.
      return keccak_256(preprocessed)
    default:
      return null
  }
}
