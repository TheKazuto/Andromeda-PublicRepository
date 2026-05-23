// Filecoin transaction decoder (advisory).
//
// A Filecoin `Message` is a CBOR array:
//   [version, to, from, nonce, value, gasLimit, gasFeeCap, gasPremium, method, params]
// We surface recipient, FIL value and the actor method (method 0 = plain send;
// anything else is an actor method call — flagged as medium).

import { blake2b } from '@noble/hashes/blake2.js'
import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'
import { parseCbor, type CborValue } from './cbor.js'
import { BASE32_RFC4648_LOWER, base32Encode } from './base32.js'

function filecoinAddress(bytes: Uint8Array): string {
  if (bytes.length === 0) return '(empty)'
  const protocol = bytes[0]!
  const payload = bytes.subarray(1)
  if (protocol === 0) {
    // ID address: payload is a LEB128 actor id.
    let result = 0n
    let shift = 0n
    for (const b of payload) {
      result |= BigInt(b & 0x7f) << shift
      if ((b & 0x80) === 0) break
      shift += 7n
    }
    return `f0${result.toString()}`
  }
  // secp256k1 (1) / actor (2) / BLS (3) / delegated (4): base32(payload || checksum4).
  const checksum = blake2b(bytes, { dkLen: 4 })
  const data = new Uint8Array(payload.length + 4)
  data.set(payload, 0)
  data.set(checksum, payload.length)
  return `f${protocol}${base32Encode(data, BASE32_RFC4648_LOWER)}`
}

// Filecoin BigInt: empty = 0; else first byte is the sign, rest big-endian magnitude.
function bigFromBytes(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n
  let v = 0n
  for (let i = 1; i < bytes.length; i += 1) v = (v << 8n) | BigInt(bytes[i]!)
  return bytes[0] === 1 ? -v : v
}

// 1 FIL = 10^18 attoFIL.
function formatFil(atto: bigint): string {
  const whole = atto / 10n ** 18n
  const frac = (atto % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

function asBytes(v: CborValue | undefined): Uint8Array | undefined {
  return v instanceof Uint8Array ? v : undefined
}

function decodeFilecoin(payloadHex: string): CalldataRisk {
  try {
    const msg = parseCbor(hexToBytes(payloadHex))
    if (!Array.isArray(msg) || msg.length < 10) throw new Error('not a Filecoin message')

    const to = asBytes(msg[1])
    const value = asBytes(msg[4])
    const method = typeof msg[8] === 'bigint' ? msg[8] : 0n
    if (!to) throw new Error('no recipient')

    const dest = filecoinAddress(to)
    const amount = value ? bigFromBytes(value) : 0n

    const reasons: string[] = []
    let level: CalldataRisk['level'] = 'none'

    if (amount > 0n) reasons.push(`transfer ${formatFil(amount)} FIL to ${dest}`)
    if (method !== 0n) {
      reasons.push(`actor method ${method.toString()} call on ${dest}; verify the actor`)
      level = 'medium'
    } else if (reasons.length === 0) {
      reasons.push(`Filecoin send to ${dest}`)
    }

    return { level, reasons, effectsExtracted: true }
  } catch {
    return unverifiable('failed to decode Filecoin transaction; effects cannot be verified')
  }
}

export const filecoinDecoder: ChainDecoder = {
  family: 'Filecoin',
  decode: (payloadHex, kind) =>
    kind === 'message' ? messageSignature() : decodeFilecoin(payloadHex),
}
