// Bitcoin (and Bitcoin-like, e.g. Litecoin via bip122) transaction decoder.
//
// Parses a raw transaction (legacy or segwit) and extracts its outputs:
// destination addresses + amounts, OP_RETURN data, and non-standard scripts.
// This turns the previous "cannot verify" fallback into real, advisory effects
// (who receives how much). Address derivation reuses the repo's bech32/bs58
// deps; base58check needs only double-sha256 (no ripemd160 — the hash160 is
// already inside the scriptPubKey).

import { createHash } from 'node:crypto'
import { bech32, bech32m } from 'bech32'
import bs58 from 'bs58'
import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
  type DecodeContext,
} from './registry.js'

interface BtcNetwork {
  hrp: string // bech32 human-readable part
  p2pkh: number // base58 version byte for P2PKH
  p2sh: number // base58 version byte for P2SH
}

const MAINNET: BtcNetwork = { hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 }
const TESTNET: BtcNetwork = { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 }

// CAIP-2 bip122 reference = first 16 bytes (32 hex chars) of the genesis hash.
function networkFor(reference: string): BtcNetwork {
  // testnet3 genesis + regtest genesis prefixes
  if (reference.startsWith('000000000933ea') || reference.startsWith('0f9188f13cb7b2')) {
    return TESTNET
  }
  return MAINNET
}

class Reader {
  pos = 0
  constructor(private readonly buf: Uint8Array) {}

  u8(): number {
    const v = this.buf[this.pos]
    if (v === undefined) throw new Error('eof')
    this.pos += 1
    return v
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) throw new Error('eof')
    const s = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return s
  }

  u32le(): number {
    const b = this.bytes(4)
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0
  }

  u64le(): bigint {
    const b = this.bytes(8)
    let v = 0n
    for (let i = 7; i >= 0; i -= 1) v = (v << 8n) | BigInt(b[i]!)
    return v
  }

  varint(): number {
    const n = this.u8()
    if (n < 0xfd) return n
    if (n === 0xfd) {
      const b = this.bytes(2)
      return b[0]! | (b[1]! << 8)
    }
    if (n === 0xfe) return this.u32le()
    return Number(this.u64le())
  }

  peek(offset: number): number | undefined {
    return this.buf[this.pos + offset]
  }
}

function base58Check(version: number, payload: Uint8Array): string {
  const data = new Uint8Array(1 + payload.length)
  data[0] = version
  data.set(payload, 1)
  const c1 = createHash('sha256').update(data).digest()
  const c2 = createHash('sha256').update(c1).digest()
  const out = new Uint8Array(data.length + 4)
  out.set(data, 0)
  out.set(c2.subarray(0, 4), data.length)
  return bs58.encode(out)
}

function segwitAddress(hrp: string, witnessVersion: number, program: Uint8Array): string {
  const words = [witnessVersion, ...bech32.toWords(program)]
  const codec = witnessVersion === 0 ? bech32 : bech32m
  return codec.encode(hrp, words)
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

interface ClassifiedOutput {
  type: string
  address?: string
  dataHex?: string
}

function classifyScript(script: Uint8Array, net: BtcNetwork): ClassifiedOutput {
  // OP_RETURN (data carrier)
  if (script.length >= 1 && script[0] === 0x6a) {
    return { type: 'OP_RETURN', dataHex: toHex(script.subarray(1)) }
  }
  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  if (
    script.length === 25 &&
    script[0] === 0x76 &&
    script[1] === 0xa9 &&
    script[2] === 0x14 &&
    script[23] === 0x88 &&
    script[24] === 0xac
  ) {
    return { type: 'P2PKH', address: base58Check(net.p2pkh, script.subarray(3, 23)) }
  }
  // P2SH: OP_HASH160 <20> OP_EQUAL
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
    return { type: 'P2SH', address: base58Check(net.p2sh, script.subarray(2, 22)) }
  }
  // P2WPKH: OP_0 <20>
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
    return { type: 'P2WPKH', address: segwitAddress(net.hrp, 0, script.subarray(2)) }
  }
  // P2WSH: OP_0 <32>
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
    return { type: 'P2WSH', address: segwitAddress(net.hrp, 0, script.subarray(2)) }
  }
  // P2TR: OP_1 <32>
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return { type: 'P2TR', address: segwitAddress(net.hrp, 1, script.subarray(2)) }
  }
  return { type: 'non-standard' }
}

function formatBtc(sats: bigint): string {
  const whole = sats / 100_000_000n
  const frac = (sats % 100_000_000n).toString().padStart(8, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

function decodeBitcoin(payloadHex: string, net: BtcNetwork): CalldataRisk {
  const outputs: ClassifiedOutput[] = []
  let total = 0n
  try {
    const bytes = hexToBytes(payloadHex)
    if (bytes.length === 0) return unverifiable('empty Bitcoin payload; effects cannot be verified')

    const r = new Reader(bytes)
    r.u32le() // version

    // Optional segwit marker (0x00) + flag (0x01) right after version.
    if (r.peek(0) === 0x00 && r.peek(1) === 0x01) {
      r.u8()
      r.u8()
    }

    const vin = r.varint()
    if (vin === 0 || vin > 100_000) throw new Error('implausible input count')
    for (let i = 0; i < vin; i += 1) {
      r.bytes(36) // prevout (txid 32 + vout 4)
      const scriptLen = r.varint()
      r.bytes(scriptLen) // scriptSig
      r.u32le() // sequence
    }

    const vout = r.varint()
    if (vout === 0 || vout > 100_000) throw new Error('implausible output count')
    for (let i = 0; i < vout; i += 1) {
      const value = r.u64le()
      total += value
      const scriptLen = r.varint()
      const script = r.bytes(scriptLen)
      outputs.push(classifyScript(script, net))
    }
    // Witness data + locktime are irrelevant to the spend effects.
  } catch {
    return unverifiable('failed to decode Bitcoin transaction; effects cannot be verified')
  }

  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'
  let valueOutputs = 0

  for (let i = 0; i < outputs.length; i += 1) {
    const o = outputs[i]!
    if (o.type === 'OP_RETURN') {
      reasons.push('OP_RETURN data output (no value transfer)')
      level = maxLevel(level, 'low')
    } else if (o.type === 'non-standard') {
      reasons.push('non-standard output script; recipient cannot be resolved')
      level = maxLevel(level, 'medium')
    } else {
      valueOutputs += 1
      reasons.push(`send to ${o.address ?? o.type} (${o.type})`)
    }
  }

  reasons.unshift(`Bitcoin transfer: ${formatBtc(total)} BTC across ${valueOutputs} recipient output(s)`)
  return { level, reasons, effectsExtracted: true }
}

export const bitcoinDecoder: ChainDecoder = {
  family: 'Bitcoin',
  decode: (payloadHex, kind, ctx: DecodeContext) =>
    kind === 'message' ? messageSignature() : decodeBitcoin(payloadHex, networkFor(ctx.reference)),
}
