// Ika `Sign.message_metadata` builder + its on-chain digest.
//
// Most chains sign with EMPTY metadata → the on-chain MessageApproval is derived
// WITHOUT a metadata seed and `ika_msg_metadata_digest = 0`. Some schemes carry
// per-scheme metadata that the network needs at sign time:
//   - EcdsaBlake2b256 (Zcash): Blake2bMessageMetadata { personal, salt:[] }
//   - SchnorrkelMerlin (sr25519, deferred): SchnorrkelMessageMetadata { context }
//
// When metadata is non-empty, `ika_msg_metadata_digest = keccak256(metadata)`
// and the gateway adds it as the final MessageApproval PDA seed (see
// gateway/internal/policy/pda.go). The BCS here mirrors
// `engine/ika-client/bcs.ts::Blake2bMessageMetadata` byte-for-byte; both must
// stay in sync with the vendored Ika wire format.

import { keccak_256 } from '@noble/hashes/sha3.js'
import { zcashSigHashPersonal } from './zcash.js'

/** 32 zero bytes — the on-chain digest when there is no metadata. */
const ZERO32 = new Uint8Array(32)

export interface IkaMessageMetadata {
  /** BCS bytes to send as `Sign.message_metadata` ("" = no metadata). */
  metadata: Uint8Array
  /**
   * The on-chain `ika_msg_metadata_digest`: `keccak256(metadata)` when metadata
   * is non-empty, else 32 zero bytes (current behaviour for all other chains).
   */
  ikaMsgMetadataDigest: Uint8Array
}

/** ULEB128 length prefix (BCS). Our lengths are < 128 → a single byte. */
function uleb128(n: number): Uint8Array {
  const out: number[] = []
  let v = n
  do {
    let byte = v & 0x7f
    v >>>= 7
    if (v > 0) byte |= 0x80
    out.push(byte)
  } while (v > 0)
  return Uint8Array.from(out)
}

/** BCS of `Blake2bMessageMetadata { personal: vec<u8>, salt: vec<u8> }`. */
export function bcsBlake2bMetadata(personal: Uint8Array, salt: Uint8Array = new Uint8Array(0)): Uint8Array {
  const pLen = uleb128(personal.length)
  const sLen = uleb128(salt.length)
  const out = new Uint8Array(pLen.length + personal.length + sLen.length + salt.length)
  let off = 0
  out.set(pLen, off); off += pLen.length
  out.set(personal, off); off += personal.length
  out.set(sLen, off); off += sLen.length
  out.set(salt, off)
  return out
}

/** No metadata — empty bytes, zero digest. */
export function emptyMetadata(): IkaMessageMetadata {
  return { metadata: new Uint8Array(0), ikaMsgMetadataDigest: ZERO32 }
}

/** Blake2b metadata (Zcash). digest = keccak256(BCS). */
export function blake2bMetadata(personal: Uint8Array, salt?: Uint8Array): IkaMessageMetadata {
  const metadata = bcsBlake2bMetadata(personal, salt)
  return { metadata, ikaMsgMetadataDigest: keccak_256(metadata) }
}

/**
 * Resolve the Ika message metadata for a CAIP-2 namespace. Centralised so a new
 * metadata-bearing chain is one entry here, never an on-chain change.
 *
 * `opts.zcashBranchId` selects the Zcash consensus branch id (default NU5).
 */
export function metadataForNamespace(
  namespace: string,
  opts: { zcashBranchId?: number | undefined } = {},
): IkaMessageMetadata {
  switch (namespace) {
    case 'zcash':
      return blake2bMetadata(zcashSigHashPersonal(opts.zcashBranchId))
    // (future) 'polkadot' sr25519 → SchnorrkelMessageMetadata { context }
    default:
      return emptyMetadata()
  }
}
