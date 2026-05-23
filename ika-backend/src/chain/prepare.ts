// One-stop preparation of the bytes a client needs to sign for a destination
// chain. Single source of truth for the (preprocessed, digest, metadata) tuple
// so the approval step and the sign step never drift:
//
//   - `preprocessedHex` → pass as `messageHex` to POST /v1/dwallet/sign
//     (the network applies the scheme hash to it).
//   - `digestHex`       → pass as `message_digest_hex` to the PolicyEngine v3
//     `request-signature` challenge/submit (the on-chain MessageApproval).
//   - `messageMetadataHex` → pass as `messageMetadataHex` to POST /v1/dwallet/sign
//     (empty "" for chains without metadata).
//   - `ikaMsgMetadataDigestHex` → pass as `ika_msg_metadata_digest_hex` to the
//     request-signature challenge/submit (32 zero bytes when no metadata; the
//     gateway adds it as the final MessageApproval PDA seed only when non-zero).
//
// Read-only, stateless, no private material.

import { type CurveName } from '../engine/ika-client/bcs.js'
import { resolveChainParams, parseChainId } from './chains.js'
import { preProcessForChain, type MessageKind } from './preprocess.js'
import { schemeDigest } from './digest.js'
import { metadataForNamespace } from './metadata.js'
import { buildZip243Preimage, type ZcashTxFields } from './zcash.js'
import { UnsupportedChainError } from './errors.js'

export interface PreparedMessage {
  chainId: string
  curve: CurveName
  /** On-wire `DWalletSignatureScheme` numeric id for this chain. */
  scheme: number
  kind: MessageKind
  /** Envelope-applied bytes to sign (`messageHex` for POST /v1/dwallet/sign). */
  preprocessedHex: string
  /**
   * The on-chain `message_digest` (`message_digest_hex` for request-signature) =
   * `keccak256(preprocessed)` for every supported scheme, or `null` for an
   * unrecognized scheme.
   */
  digestHex: string | null
  /** BCS `Sign.message_metadata` ("" when the chain carries no metadata). */
  messageMetadataHex: string
  /**
   * `ika_msg_metadata_digest_hex` for request-signature: `keccak256(metadata)`
   * when metadata is non-empty, else 32 zero bytes (current behaviour for all
   * non-Zcash chains).
   */
  ikaMsgMetadataDigestHex: string
}

function toHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 1) s += bytes[i]!.toString(16).padStart(2, '0')
  return s
}

/**
 * Resolve the chain, apply its envelope, compute the scheme digest, and the
 * (empty, for non-Zcash) Ika message metadata.
 *
 * Zcash is NOT handled here — it needs structured tx fields; use
 * {@link prepareZcashMessage}.
 *
 * @throws {ChainIdParseError} / {UnsupportedChainError} via `resolveChainParams`.
 */
export function prepareMessage(chainId: string, payload: Uint8Array, kind: MessageKind): PreparedMessage {
  const { curve, scheme } = resolveChainParams(chainId)
  const { namespace } = parseChainId(chainId)
  if (namespace === 'zcash') {
    // Guard: Zcash requires structured fields (see prepareZcashMessage). Falling
    // through here would produce an empty/wrong preimage. The route never hits
    // this (it dispatches zcash to prepareZcashMessage); it's a defensive guard
    // for direct programmatic callers.
    throw new UnsupportedChainError(chainId, ['zcash (call prepareZcashMessage with structured tx fields)'])
  }
  const preprocessed = preProcessForChain(chainId, payload, kind)
  const digest = schemeDigest(scheme, preprocessed)
  const md = metadataForNamespace(namespace)
  return {
    chainId,
    curve,
    scheme,
    kind,
    preprocessedHex: toHex(preprocessed),
    digestHex: digest ? toHex(digest) : null,
    messageMetadataHex: toHex(md.metadata),
    ikaMsgMetadataDigestHex: toHex(md.ikaMsgMetadataDigest),
  }
}

/**
 * Prepare a Zcash TRANSPARENT (ZIP-243) sign request from structured tx fields.
 * Builds the preimage (the `message` to sign), the keccak256 approval digest,
 * and the BLAKE2b message metadata (personalized by the consensus branch id).
 *
 * @throws {UnsupportedChainError} when `chainId` is not a Zcash chain.
 * @throws {RangeError} on malformed tx fields (via buildZip243Preimage).
 */
export function prepareZcashMessage(chainId: string, fields: ZcashTxFields): PreparedMessage {
  const { curve, scheme } = resolveChainParams(chainId)
  const { namespace } = parseChainId(chainId)
  if (namespace !== 'zcash') {
    throw new UnsupportedChainError(chainId, ['zcash'])
  }
  const preimage = buildZip243Preimage(fields)
  const digest = schemeDigest(scheme, preimage) // keccak256(preimage)
  const md = metadataForNamespace('zcash', { zcashBranchId: fields.branchId })
  return {
    chainId,
    curve,
    scheme,
    kind: 'transaction',
    preprocessedHex: toHex(preimage),
    digestHex: digest ? toHex(digest) : null,
    messageMetadataHex: toHex(md.metadata),
    ikaMsgMetadataDigestHex: toHex(md.ikaMsgMetadataDigest),
  }
}
