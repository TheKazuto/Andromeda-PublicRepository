// Zcash transparent (ZIP-243) sighash preimage construction.
//
// Scope: TRANSPARENT inputs only (t-addresses, secp256k1 + EcdsaBlake2b256,
// scheme 4). Shielded (z-address, zk-SNARK) is out of scope — the Ika network
// only signs the transparent ECDSA path.
//
// The Ika network signs `BLAKE2b-256(preimage, personal = "ZcashSigHash" ||
// consensus_branch_id)`. The personalization is delivered to the network via
// `Sign.message_metadata = BCS(Blake2bMessageMetadata { personal, salt:[] })`
// (see metadata.ts). The on-chain MessageApproval is keyed by
// `keccak256(preimage)` like every other chain (see digest.ts) — the BLAKE2b is
// the network's sign-time hash, not the approval key.
//
// Ported from clear-msig `programs/clear-wallet/src/chains/zcash.rs` and the
// ZIP-243 spec (https://zips.z.cash/zip-0243). This builds a v4 (Overwintered,
// Sapling version group) transparent sighash, which remains valid under NU5
// using the NU5 consensus branch id.
//
// PRE-ALPHA: the network runs a mock signer, so the Zcash signature is NOT
// validated end-to-end live. Correctness of this preimage is asserted by the
// fixture (fixtures/chain) only — validate against an official ZIP-243 test
// vector + a Zcash node before any real use.

import { blake2b } from '@noble/hashes/blake2.js'

// ── consensus branch ids (u32) ──────────────────────────────────────────────
/** NU5 consensus branch id. Default for Zcash mainnet today. */
export const ZCASH_BRANCH_NU5 = 0xc2d6d0b4
/** Sapling consensus branch id. */
export const ZCASH_BRANCH_SAPLING = 0x76b809bb

// ── fixed v4 / Sapling-version-group constants ──────────────────────────────
const HEADER_V4_OVERWINTERED = 0x80000004 // fOverwintered=1, version=4
const VERSION_GROUP_ID_SAPLING = 0x892f2085
const SIGHASH_ALL = 1

// BLAKE2b personalization tags (16 bytes each, ASCII).
const P_PREVOUTS = new TextEncoder().encode('ZcashPrevoutHash')
const P_SEQUENCE = new TextEncoder().encode('ZcashSequencHash')
const P_OUTPUTS = new TextEncoder().encode('ZcashOutputsHash')
const SIGHASH_TAG = new TextEncoder().encode('ZcashSigHash') // 12 bytes

// ── input model ─────────────────────────────────────────────────────────────

export interface ZcashTxInput {
  /**
   * 32-byte prevout txid, hex, in ZIP-243 WIRE (internal) byte order — i.e. the
   * raw bytes as they appear in the outpoint, which is the REVERSE of the
   * big-endian txid shown by block explorers. The caller is responsible for the
   * byte order; this module does not reverse it.
   */
  txidHex: string
  /** prevout index (u32). */
  vout: number
  /** nSequence (u32). Defaults to 0xffffffff. */
  sequence?: number | undefined
}

export interface ZcashTxOutput {
  /** Output value in zatoshis (u64). */
  value: bigint
  /** scriptPubKey, hex, WITHOUT a length prefix (this module adds CompactSize). */
  scriptPubKeyHex: string
}

export interface ZcashSignTarget {
  /** Index into `inputs` of the input being signed. */
  inputIndex: number
  /**
   * scriptCode for the signed input, hex, WITHOUT a length prefix. For P2PKH
   * this is the 25-byte scriptPubKey `76 a9 14 <pkh20> 88 ac`.
   */
  scriptCodeHex: string
  /** Value in zatoshis of the output being spent (u64). */
  amount: bigint
}

export interface ZcashTxFields {
  inputs: ZcashTxInput[]
  outputs: ZcashTxOutput[]
  signTarget: ZcashSignTarget
  /** nLockTime (u32). Default 0. */
  lockTime?: number | undefined
  /** nExpiryHeight (u32). Default 0. */
  expiryHeight?: number | undefined
  /** consensus branch id (u32). Default NU5. */
  branchId?: number | undefined
  /** SIGHASH type (u32). Default 1 (SIGHASH_ALL). Only ALL is supported. */
  hashType?: number | undefined
}

// ── byte helpers ─────────────────────────────────────────────────────────────

function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`u32 out of range: ${n}`)
  }
  const b = new Uint8Array(4)
  b[0] = n & 0xff
  b[1] = (n >>> 8) & 0xff
  b[2] = (n >>> 16) & 0xff
  b[3] = (n >>> 24) & 0xff
  return b
}

function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new RangeError(`u64 out of range: ${v}`)
  }
  const b = new Uint8Array(8)
  let x = v
  for (let i = 0; i < 8; i += 1) {
    b[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return b
}

function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.from([n])
  if (n <= 0xffff) return Uint8Array.from([0xfd, n & 0xff, (n >> 8) & 0xff])
  return Uint8Array.from([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff])
}

function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  if (h.length % 2 !== 0) throw new RangeError('hex must be even-length')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    const byte = parseInt(h.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) throw new RangeError(`invalid hex: ${hex}`)
    out[i] = byte
  }
  return out
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

function blake2bPersonal(data: Uint8Array, personal: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32, personalization: personal })
}

// ── ZIP-243 sub-hashes ───────────────────────────────────────────────────────

function hashPrevouts(inputs: ZcashTxInput[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const i of inputs) {
    const txid = fromHex(i.txidHex)
    if (txid.length !== 32) throw new RangeError('txidHex must be 32 bytes')
    parts.push(txid, u32le(i.vout))
  }
  return blake2bPersonal(concat(parts), P_PREVOUTS)
}

function hashSequence(inputs: ZcashTxInput[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const i of inputs) parts.push(u32le(i.sequence ?? 0xffffffff))
  return blake2bPersonal(concat(parts), P_SEQUENCE)
}

function hashOutputs(outputs: ZcashTxOutput[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const o of outputs) {
    const script = fromHex(o.scriptPubKeyHex)
    parts.push(u64le(o.value), compactSize(script.length), script)
  }
  return blake2bPersonal(concat(parts), P_OUTPUTS)
}

// ── personal for the final sighash (delivered as message_metadata) ───────────

/** `"ZcashSigHash"(12) || consensus_branch_id(4 LE)` — the 16-byte BLAKE2b personal. */
export function zcashSigHashPersonal(branchId: number = ZCASH_BRANCH_NU5): Uint8Array {
  const personal = new Uint8Array(16)
  personal.set(SIGHASH_TAG, 0)
  personal.set(u32le(branchId), 12)
  return personal
}

// ── preimage ─────────────────────────────────────────────────────────────────

/**
 * Build the ZIP-243 transparent sighash preimage. The returned bytes are the
 * `message` to sign (the network applies `BLAKE2b-256(preimage, personal)`),
 * and `keccak256(preimage)` is the on-chain MessageApproval digest.
 *
 * @throws {RangeError} on malformed fields.
 */
export function buildZip243Preimage(fields: ZcashTxFields): Uint8Array {
  const { inputs, outputs, signTarget } = fields
  if (inputs.length === 0) throw new RangeError('zcash: at least one input is required')
  if (signTarget.inputIndex < 0 || signTarget.inputIndex >= inputs.length) {
    throw new RangeError('zcash: signTarget.inputIndex out of range')
  }
  const hashType = fields.hashType ?? SIGHASH_ALL
  if (hashType !== SIGHASH_ALL) {
    throw new RangeError('zcash: only SIGHASH_ALL (1) is supported')
  }
  const signed = inputs[signTarget.inputIndex]!
  const scriptCode = fromHex(signTarget.scriptCodeHex)

  return concat([
    u32le(HEADER_V4_OVERWINTERED), // nHeader
    u32le(VERSION_GROUP_ID_SAPLING), // nVersionGroupId
    hashPrevouts(inputs), // hashPrevouts
    hashSequence(inputs), // hashSequence
    hashOutputs(outputs), // hashOutputs
    new Uint8Array(32), // hashJoinSplits (transparent → zero)
    new Uint8Array(32), // hashShieldedSpends
    new Uint8Array(32), // hashShieldedOutputs
    u32le(fields.lockTime ?? 0), // nLockTime
    u32le(fields.expiryHeight ?? 0), // nExpiryHeight
    u64le(0n), // valueBalance (transparent → 0)
    u32le(hashType), // nHashType
    // ── the transparent input being signed ──
    fromHex(signed.txidHex), // outpoint: txid (32)
    u32le(signed.vout), // outpoint: index (4)
    compactSize(scriptCode.length), // scriptCode length (CompactSize)
    scriptCode, // scriptCode
    u64le(signTarget.amount), // amount of the output being spent
    u32le(signed.sequence ?? 0xffffffff), // nSequence of the signed input
  ])
}
