// Recovery — Bitcoin signed message.
//
// Two schemes are supported via the same verifier:
//   • BIP-137 — legacy "Bitcoin Signed Message" (P2PKH, P2SH-P2WPKH, P2WPKH)
//   • BIP-322 simple — taproot key-path (P2TR, `bc1p…` / `tb1p…`)
//
// The verifier dispatches based on the address prefix: anything starting
// with `bc1p` or `tb1p` goes through the BIP-322 path; everything else
// uses the BIP-137 magic-hash recover path. Multi-sig taproot, P2WSH, and
// BIP-322 full (with prevouts) remain follow-ups — most consumer wallets
// (Sparrow, OKX, Xverse) emit BIP-322-simple for key-path P2TR.

import { createHash } from 'node:crypto'
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bech32, bech32m } from 'bech32'
import { ripemd160 } from '@noble/hashes/legacy.js'
import bs58 from 'bs58'
import {
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const SIGNATURE_LENGTH = 65
const COMPRESSED_PUBKEY_LENGTH = 33

function doubleSha256(input: Uint8Array): Buffer {
  const first = createHash('sha256').update(input).digest()
  return createHash('sha256').update(first).digest()
}

function hash160(input: Uint8Array): Buffer {
  const sha = createHash('sha256').update(input).digest()
  return Buffer.from(ripemd160(sha))
}

function bitcoinMessageMagicHash(message: string): Buffer {
  const messageBytes = Buffer.from(message, 'utf8')
  const prefixBytes = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8')
  let lenBuf: Buffer
  if (messageBytes.length < 0xfd) {
    lenBuf = Buffer.from([messageBytes.length])
  } else if (messageBytes.length <= 0xffff) {
    lenBuf = Buffer.alloc(3)
    lenBuf[0] = 0xfd
    lenBuf.writeUInt16LE(messageBytes.length, 1)
  } else {
    lenBuf = Buffer.alloc(5)
    lenBuf[0] = 0xfe
    lenBuf.writeUInt32LE(messageBytes.length, 1)
  }
  return doubleSha256(Buffer.concat([prefixBytes, lenBuf, messageBytes]))
}

function parseHeader(headerByte: number): { recoveryId: number; compressed: boolean } | null {
  if (headerByte < 27 || headerByte > 42) return null
  const offset = (headerByte - 27) % 4
  return { recoveryId: offset, compressed: headerByte >= 31 }
}

function p2pkhAddress(pubkey: Uint8Array, mainnet: boolean): string {
  const h160 = hash160(pubkey)
  const versionByte = mainnet ? 0x00 : 0x6f
  const payload = Buffer.concat([Buffer.from([versionByte]), h160])
  const checksum = doubleSha256(payload).subarray(0, 4)
  return bs58.encode(Buffer.concat([payload, checksum]))
}

function p2shP2wpkhAddress(pubkey: Uint8Array, mainnet: boolean): string {
  const h160 = hash160(pubkey)
  const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), h160])
  const scriptHash = hash160(redeemScript)
  const versionByte = mainnet ? 0x05 : 0xc4
  const payload = Buffer.concat([Buffer.from([versionByte]), scriptHash])
  const checksum = doubleSha256(payload).subarray(0, 4)
  return bs58.encode(Buffer.concat([payload, checksum]))
}

function p2wpkhAddress(pubkey: Uint8Array, mainnet: boolean): string {
  const h160 = hash160(pubkey)
  const hrp = mainnet ? 'bc' : 'tb'
  const words = [0, ...bech32.toWords(h160)]
  return bech32.encode(hrp, words)
}

function looksLikeTaproot(walletAddress: string): boolean {
  const trimmed = walletAddress.trim()
  return trimmed.startsWith('bc1p') || trimmed.startsWith('tb1p')
}

// ── BIP-322 simple (P2TR key-path) ───────────────────────────────────────

/**
 * Decode a `bc1p…` / `tb1p…` address into the 32-byte x-only tweaked
 * output public key it commits to. Returns null if the address is malformed
 * or witness version != 1.
 */
function decodeTaprootAddress(address: string): { tweakedXOnly: Buffer; mainnet: boolean } | null {
  const trimmed = address.trim()
  const expectedHrp = trimmed.startsWith('bc1p') ? 'bc' : trimmed.startsWith('tb1p') ? 'tb' : null
  if (!expectedHrp) return null
  let decoded: ReturnType<typeof bech32m.decode>
  try {
    decoded = bech32m.decode(trimmed)
  } catch {
    return null
  }
  if (decoded.prefix !== expectedHrp) return null
  const words = decoded.words
  if (words.length === 0 || words[0] !== 1) return null // witness version
  const program = Buffer.from(bech32m.fromWords(words.slice(1)))
  if (program.length !== 32) return null
  return { tweakedXOnly: program, mainnet: expectedHrp === 'bc' }
}

function doubleSha256Buf(input: Uint8Array): Buffer {
  return doubleSha256(input)
}

/** BIP-340 tagged hash. */
function taggedHash(tag: string, ...parts: Uint8Array[]): Buffer {
  const tagHash = sha256(Buffer.from(tag, 'utf8'))
  const total = parts.reduce((n, p) => n + p.length, 0)
  const buf = Buffer.alloc(64 + total)
  buf.set(tagHash, 0)
  buf.set(tagHash, 32)
  let off = 64
  for (const p of parts) {
    buf.set(p, off)
    off += p.length
  }
  return Buffer.from(sha256(buf))
}

/** Bitcoin CompactSize (varint). Caller ensures n < 2^53. */
function compactSize(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n])
  if (n <= 0xffff) {
    const b = Buffer.alloc(3)
    b[0] = 0xfd
    b.writeUInt16LE(n, 1)
    return b
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5)
    b[0] = 0xfe
    b.writeUInt32LE(n, 1)
    return b
  }
  // 64-bit length isn't reachable for our use case (single tx).
  throw new Error('compactSize: value out of range')
}

function u32LE(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(n >>> 0, 0)
  return b
}

function u64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(n, 0)
  return b
}

/**
 * Build the to_spend transaction (BIP-322 §"Common Specification").
 * Returns the raw serialized tx (no witness — not needed for txid).
 */
function buildToSpendTx(messageHash: Buffer, scriptPubKey: Buffer): Buffer {
  // tx version = 0
  // input count = 1
  //   prev txid = 0x00...00
  //   prev vout = 0xFFFFFFFF
  //   scriptSig = OP_0 (0x00) + OP_PUSH32 (0x20) + message_hash[32]
  //   sequence = 0x00000000
  // output count = 1
  //   value = 0
  //   scriptPubKey = <addr scriptPubKey>
  // locktime = 0
  const scriptSig = Buffer.concat([Buffer.from([0x00, 0x20]), messageHash])
  return Buffer.concat([
    u32LE(0), // version
    compactSize(1), // input count
    Buffer.alloc(32, 0), // prev txid
    u32LE(0xffffffff), // prev vout
    compactSize(scriptSig.length),
    scriptSig,
    u32LE(0), // sequence
    compactSize(1), // output count
    u64LE(0n), // value
    compactSize(scriptPubKey.length),
    scriptPubKey,
    u32LE(0), // locktime
  ])
}

/**
 * Compute BIP-341 SIGHASH_DEFAULT (key-path) over the to_sign virtual tx.
 * to_sign references to_spend.vout[0]; the only output is OP_RETURN with no data.
 */
function buildBip341Sighash(
  toSpendTxid: Buffer,
  scriptPubKey: Buffer,
): Buffer {
  // Outpoint: txid + vout (4 bytes LE = 0)
  const outpoint = Buffer.concat([toSpendTxid, u32LE(0)])
  const hashPrevouts = sha256(outpoint)
  const hashAmounts = sha256(u64LE(0n))
  const scriptPubKeySer = Buffer.concat([compactSize(scriptPubKey.length), scriptPubKey])
  const hashScriptPubKeys = sha256(scriptPubKeySer)
  const hashSequences = sha256(u32LE(0))
  // Output: value (0) + scriptPubKey for OP_RETURN
  // OP_RETURN with no data is a single 0x6a byte; serialized as
  // <varint len=1><0x6a>.
  const opReturn = Buffer.from([0x6a])
  const outputSer = Buffer.concat([u64LE(0n), compactSize(opReturn.length), opReturn])
  const hashOutputs = sha256(outputSer)

  // Key-path spend with no annex: spend_type = 0x00.
  // hash_type = 0 (SIGHASH_DEFAULT), but the BIP-341 sighash skips the
  // hash_type byte when default — the extra epoch byte is 0x00.
  const epoch = Buffer.from([0x00])
  const hashType = Buffer.from([0x00]) // SIGHASH_DEFAULT
  const version = u32LE(0) // to_sign tx version
  const locktime = u32LE(0)
  const spendType = Buffer.from([0x00])
  const inputIndex = u32LE(0)

  return taggedHash(
    'TapSighash',
    epoch,
    hashType,
    version,
    locktime,
    Buffer.from(hashPrevouts),
    Buffer.from(hashAmounts),
    Buffer.from(hashScriptPubKeys),
    Buffer.from(hashSequences),
    Buffer.from(hashOutputs),
    spendType,
    inputIndex,
  )
}

/** Decode a BIP-322-simple signature (base64 of WitnessSerialized). */
function decodeBip322Witness(b64Sig: string): Buffer[] | null {
  let raw: Buffer
  try {
    raw = Buffer.from(b64Sig.trim(), 'base64')
  } catch {
    return null
  }
  if (raw.length === 0) return null
  // Witness format: <count varint> { <len varint><bytes> }*
  let off = 0
  const readVarInt = (): number | null => {
    if (off >= raw.length) return null
    const first = raw[off]!
    off += 1
    if (first < 0xfd) return first
    if (first === 0xfd) {
      if (off + 2 > raw.length) return null
      const v = raw.readUInt16LE(off)
      off += 2
      return v
    }
    if (first === 0xfe) {
      if (off + 4 > raw.length) return null
      const v = raw.readUInt32LE(off)
      off += 4
      return v
    }
    return null // 8-byte varint not supported (witnesses don't reach this size)
  }
  const count = readVarInt()
  if (count === null) return null
  const stack: Buffer[] = []
  for (let i = 0; i < count; i++) {
    const len = readVarInt()
    if (len === null) return null
    if (off + len > raw.length) return null
    stack.push(raw.subarray(off, off + len))
    off += len
  }
  if (off !== raw.length) return null
  return stack
}

async function verifyBip322Taproot(input: VerifyInput): Promise<boolean> {
  const decoded = decodeTaprootAddress(input.walletAddress)
  if (!decoded) return false
  const tweakedXOnly = decoded.tweakedXOnly

  const witness = decodeBip322Witness(input.signature)
  if (!witness || witness.length !== 1) return false // key-path: stack of 1
  let sig = witness[0]!
  if (sig.length === 65) {
    // Final byte is the sighash flag — only SIGHASH_DEFAULT (0x00) supported.
    if (sig[64] !== 0x00) return false
    sig = sig.subarray(0, 64)
  }
  if (sig.length !== 64) return false

  // P2TR scriptPubKey = OP_1 (0x51) + OP_PUSH32 (0x20) + 32-byte tweaked key.
  const scriptPubKey = Buffer.concat([Buffer.from([0x51, 0x20]), tweakedXOnly])

  const messageHash = taggedHash('BIP0322-signed-message', Buffer.from(input.message, 'utf8'))
  const toSpendRaw = buildToSpendTx(messageHash, scriptPubKey)
  // Bitcoin txid = double-sha256 of serialized tx (no witness), little-endian.
  // For BIP-341 sighash we use the 32-byte hash directly (already big-endian
  // internally via sha256). The convention in BIP-341 is to use the raw 32
  // bytes (no reversal) for the prevouts entry.
  const toSpendTxid = doubleSha256Buf(toSpendRaw)

  const sighash = buildBip341Sighash(toSpendTxid, scriptPubKey)

  try {
    return schnorr.verify(sig, sighash, tweakedXOnly)
  } catch {
    return false
  }
}

// ── Verifier registration ────────────────────────────────────────────────

export const secp256k1BitcoinVerifier: SchemeVerifier = {
  scheme: 'secp256k1-bitcoin',
  async verify(input: VerifyInput): Promise<boolean> {
    if (looksLikeTaproot(input.walletAddress)) {
      return verifyBip322Taproot(input)
    }
    const sigBytes = decodeSignatureBytes(input.signature)
    if (!sigBytes || sigBytes.length !== SIGNATURE_LENGTH) return false
    const headerInfo = parseHeader(sigBytes[0]!)
    if (!headerInfo) return false
    const r = sigBytes.subarray(1, 33)
    const s = sigBytes.subarray(33, 65)
    const digest = bitcoinMessageMagicHash(input.message)
    let recoveredPubkey: Uint8Array
    try {
      const recoveredFormat = Buffer.concat([Buffer.from([headerInfo.recoveryId]), r, s])
      const uncompressed = secp256k1.recoverPublicKey(recoveredFormat, digest, { prehash: false })
      const point = secp256k1.Point.fromBytes(uncompressed)
      recoveredPubkey = point.toBytes(headerInfo.compressed)
    } catch {
      return false
    }
    if (!headerInfo.compressed && recoveredPubkey.length !== 65) return false
    if (headerInfo.compressed && recoveredPubkey.length !== COMPRESSED_PUBKEY_LENGTH) return false
    const candidates: string[] = []
    for (const mainnet of [true, false]) {
      candidates.push(p2pkhAddress(recoveredPubkey, mainnet))
      if (recoveredPubkey.length === COMPRESSED_PUBKEY_LENGTH) {
        candidates.push(p2shP2wpkhAddress(recoveredPubkey, mainnet))
        candidates.push(p2wpkhAddress(recoveredPubkey, mainnet))
      }
    }
    return candidates.includes(input.walletAddress.trim())
  },
}

registerVerifier(secp256k1BitcoinVerifier)
