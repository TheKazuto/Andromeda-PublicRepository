// Algorand transaction decoder (advisory).
//
// An Algorand transaction is a canonical msgpack map (optionally prefixed with
// "TX" before signing). We read the standard fields — `type`, receiver, amount,
// asset/app ids — and surface recipients + amounts. Payments and asset transfers
// are low-noise; application calls are flagged as medium (smart-contract code).

import { createHash } from 'node:crypto'
import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'
import { parseMsgpack, type MsgpackValue } from './msgpack.js'
import { BASE32_RFC4648_UPPER, base32Encode } from './base32.js'

function algorandAddress(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) return `0x${Buffer.from(pubkey).toString('hex')}`
  const checksum = createHash('sha512-256').update(pubkey).digest().subarray(28, 32)
  const full = new Uint8Array(36)
  full.set(pubkey, 0)
  full.set(checksum, 32)
  return base32Encode(full, BASE32_RFC4648_UPPER)
}

function asBig(v: MsgpackValue | undefined): bigint {
  return typeof v === 'bigint' ? v : 0n
}

function asBytes(v: MsgpackValue | undefined): Uint8Array | undefined {
  return v instanceof Uint8Array ? v : undefined
}

function decodeAlgorand(payloadHex: string): CalldataRisk {
  let tx: { [k: string]: MsgpackValue }
  try {
    let bytes = hexToBytes(payloadHex)
    if (bytes.length === 0) return unverifiable('empty Algorand payload; effects cannot be verified')
    // Optional "TX" domain prefix added before signing.
    if (bytes[0] === 0x54 && bytes[1] === 0x58) bytes = bytes.subarray(2)
    const parsed = parseMsgpack(bytes)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || parsed instanceof Uint8Array) {
      throw new Error('not a map')
    }
    tx = parsed
  } catch {
    return unverifiable('failed to decode Algorand transaction; effects cannot be verified')
  }

  const type = typeof tx['type'] === 'string' ? tx['type'] : ''
  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'

  switch (type) {
    case 'pay': {
      const rcv = asBytes(tx['rcv'])
      const amt = asBig(tx['amt'])
      reasons.push(
        `send ${(Number(amt) / 1e6).toString()} ALGO to ${rcv ? algorandAddress(rcv) : '(unknown)'}`,
      )
      if (asBytes(tx['close'])) {
        reasons.push('account close-out present (remaining balance is swept)')
        level = maxLevel(level, 'high')
      }
      break
    }
    case 'axfer': {
      const arcv = asBytes(tx['arcv'])
      const aamt = asBig(tx['aamt'])
      const xaid = asBig(tx['xaid'])
      reasons.push(`transfer ${aamt.toString()} of asset ${xaid.toString()} to ${arcv ? algorandAddress(arcv) : '(unknown)'}`)
      if (asBytes(tx['aclose'])) {
        reasons.push('asset close-out present (remaining asset balance is swept)')
        level = maxLevel(level, 'high')
      }
      break
    }
    case 'appl': {
      const apid = asBig(tx['apid'])
      reasons.push(`application call (app ${apid.toString()}); verify the contract`)
      level = maxLevel(level, 'medium')
      break
    }
    case 'acfg':
      reasons.push('asset configuration transaction')
      level = maxLevel(level, 'medium')
      break
    case 'keyreg':
      reasons.push('key registration transaction')
      level = maxLevel(level, 'low')
      break
    case 'afrz':
      reasons.push('asset freeze transaction')
      level = maxLevel(level, 'medium')
      break
    default:
      if (!type) return unverifiable('Algorand tx: no type field; effects cannot be verified')
      reasons.push(`Algorand transaction type "${type}"`)
      level = maxLevel(level, 'low')
  }

  return { level, reasons, effectsExtracted: true }
}

export const algorandDecoder: ChainDecoder = {
  family: 'Algorand',
  decode: (payloadHex, kind) =>
    kind === 'message' ? messageSignature() : decodeAlgorand(payloadHex),
}
