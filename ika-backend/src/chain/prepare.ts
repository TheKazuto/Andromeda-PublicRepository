// One-stop preparation of the bytes a client needs to sign for a destination
// chain. Single source of truth for the (preprocessed, digest) pair so the
// approval step and the sign step never drift:
//
//   - `preprocessedHex` → pass as `messageHex` to POST /v1/dwallet/sign
//     (the network applies the scheme hash to it).
//   - `digestHex`       → pass as `message_digest_hex` to the PolicyEngine v3
//     `request-signature` challenge/submit (the on-chain MessageApproval).
//
// Read-only, stateless, no private material.

import { type CurveName } from '../engine/ika-client/bcs.js'
import { resolveChainParams } from './chains.js'
import { preProcessForChain, type MessageKind } from './preprocess.js'
import { schemeDigest } from './digest.js'

export interface PreparedMessage {
  chainId: string
  curve: CurveName
  /** On-wire `DWalletSignatureScheme` numeric id for this chain. */
  scheme: number
  kind: MessageKind
  /** Envelope-applied bytes to sign (`messageHex` for POST /v1/dwallet/sign). */
  preprocessedHex: string
  /**
   * The on-chain `message_digest` (`message_digest_hex` for request-signature),
   * or `null` for EdDSA chains where the destination digest is not a simple
   * pre-hash. When `null`, the destination chain's digest handling is the
   * client's responsibility (Solana/Sui sign flows are not yet finalized).
   */
  digestHex: string | null
}

function toHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 1) s += bytes[i]!.toString(16).padStart(2, '0')
  return s
}

/**
 * Resolve the chain, apply its envelope, and compute the scheme digest.
 * @throws {ChainIdParseError} / {UnsupportedChainError} via `resolveChainParams`.
 */
export function prepareMessage(chainId: string, payload: Uint8Array, kind: MessageKind): PreparedMessage {
  const { curve, scheme } = resolveChainParams(chainId)
  const preprocessed = preProcessForChain(chainId, payload, kind)
  const digest = schemeDigest(scheme, preprocessed)
  return {
    chainId,
    curve,
    scheme,
    kind,
    preprocessedHex: toHex(preprocessed),
    digestHex: digest ? toHex(digest) : null,
  }
}
