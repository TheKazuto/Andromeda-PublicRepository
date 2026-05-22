// Chain-specific message/transaction envelopes, applied BEFORE the hash that
// the Ika network applies from the scheme.
//
// Ported (near-verbatim) and adapted from `odws/src/chain/preprocess.ts`
// (https://github.com/Iamknownasfesal/odws). Difference from the original: we
// reject unsupported namespaces instead of silently returning raw bytes — a
// silent fallback here would produce the wrong "bytes to sign" for an
// unvalidated chain (plan: "nunca fallback silencioso").
//
// `preProcessForChain` produces the bytes that will be signed; the on-chain
// `MessageApproval.message_digest` is `hash_scheme(preprocessed)`. The client
// (or the future /v1/dwallet/prepare-message endpoint) uses the same value in
// both the approval and the sign step, so the envelope lives in exactly one
// place.

import { blake2b } from '@noble/hashes/blake2.js'
import { resolveChainParams, parseChainId } from './chains.js'

export type MessageKind = 'transaction' | 'message'

/**
 * Apply the chain-specific envelope for `chainId` to `bytes`.
 *
 * For transactions, most chains expect the raw serialized tx bytes (the network
 * hashes them per the scheme). For messages, each chain has its own prefix.
 *
 * @throws {ChainIdParseError} / {UnsupportedChainError} via `resolveChainParams`.
 */
export function preProcessForChain(chainId: string, bytes: Uint8Array, kind: MessageKind): Uint8Array {
  // Validate the chain is supported (throws for unknown namespaces).
  resolveChainParams(chainId)
  const { namespace } = parseChainId(chainId)

  switch (namespace) {
    case 'eip155': {
      // EIP-191 personal_sign: "\x19Ethereum Signed Message:\n{len}{msg}".
      if (kind === 'message') return prefixMessage(`\x19Ethereum Signed Message:\n${bytes.length}`, bytes)
      return bytes
    }
    case 'tron': {
      // Tron personal message: "\x19TRON Signed Message:\n{len}{msg}".
      if (kind === 'message') return prefixMessage(`\x19TRON Signed Message:\n${bytes.length}`, bytes)
      return bytes
    }
    case 'bip122': {
      // Bitcoin: "\x18Bitcoin Signed Message:\n" + CompactSize(len) + msg.
      if (kind === 'message') {
        const header = new TextEncoder().encode('\x18Bitcoin Signed Message:\n')
        const lenBytes = compactSizeEncode(bytes.length)
        const wrapped = new Uint8Array(header.length + lenBytes.length + bytes.length)
        wrapped.set(header, 0)
        wrapped.set(lenBytes, header.length)
        wrapped.set(bytes, header.length + lenBytes.length)
        return wrapped
      }
      return bytes
    }
    case 'tezos': {
      // Tezos signs blake2b-256(watermark || bytes). 0x03 = operation, 0x05 = message.
      const watermark = kind === 'message' ? 0x05 : 0x03
      const wm = new Uint8Array(1 + bytes.length)
      wm[0] = watermark
      wm.set(bytes, 1)
      return blake2b(wm, { dkLen: 32 })
    }
    case 'iota':
    case 'sui': {
      // Sui / IOTA Rebased intent message + blake2b-256. scope 3 =
      // PersonalMessage (BCS ULEB128 length-prefixed), scope 0 = TransactionData.
      if (kind === 'message') {
        const lenBytes = uleb128Encode(bytes.length)
        const bcsMsg = new Uint8Array(lenBytes.length + bytes.length)
        bcsMsg.set(lenBytes, 0)
        bcsMsg.set(bytes, lenBytes.length)
        const intent = new Uint8Array(3 + bcsMsg.length)
        intent.set([3, 0, 0], 0)
        intent.set(bcsMsg, 3)
        return blake2b(intent, { dkLen: 32 })
      }
      const intent = new Uint8Array(3 + bytes.length)
      intent.set([0, 0, 0], 0)
      intent.set(bytes, 3)
      return blake2b(intent, { dkLen: 32 })
    }
    // solana, cosmos: no envelope — the raw bytes are what gets hashed.
    default:
      return bytes
  }
}

/** Prefix a message with a string header. */
function prefixMessage(header: string, msg: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(header)
  const out = new Uint8Array(prefix.length + msg.length)
  out.set(prefix, 0)
  out.set(msg, prefix.length)
  return out
}

/** Bitcoin CompactSize encoding. */
function compactSizeEncode(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n])
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff])
  return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff])
}

/** ULEB128 (BCS) length encoding. */
function uleb128Encode(n: number): Uint8Array {
  const bytes: number[] = []
  let val = n
  do {
    let byte = val & 0x7f
    val >>>= 7
    if (val > 0) byte |= 0x80
    bytes.push(byte)
  } while (val > 0)
  return new Uint8Array(bytes)
}
