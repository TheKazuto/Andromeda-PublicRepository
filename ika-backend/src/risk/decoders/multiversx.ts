// MultiversX (EGLD) transaction decoder (advisory).
//
// A MultiversX transaction is signed over its canonical JSON form, so the
// payload is UTF-8 JSON: { nonce, value, receiver, sender, gasLimit, data, … }.
// `data` is base64 — for transfers/contract calls it carries the function name
// (e.g. "ESDTTransfer@…"). We surface recipient, EGLD value and the call type.

import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'

const TOKEN_TRANSFER_FUNCS = new Set<string>([
  'ESDTTransfer',
  'ESDTNFTTransfer',
  'MultiESDTNFTTransfer',
])

// 1 EGLD = 10^18.
function formatEgld(raw: string): string {
  let v: bigint
  try {
    v = BigInt(raw)
  } catch {
    return raw
  }
  const whole = v / 10n ** 18n
  const frac = (v % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

interface MvxTx {
  receiver?: unknown
  value?: unknown
  data?: unknown
}

function decodeMultiversX(payloadHex: string): CalldataRisk {
  let tx: MvxTx
  try {
    const json = new TextDecoder().decode(hexToBytes(payloadHex))
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed !== 'object' || parsed === null) throw new Error('not an object')
    tx = parsed as MvxTx
    if (typeof tx.receiver !== 'string') throw new Error('no receiver')
  } catch {
    return unverifiable('failed to decode MultiversX transaction; effects cannot be verified')
  }

  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'
  const receiver = String(tx.receiver)
  const value = typeof tx.value === 'string' ? tx.value : '0'

  if (value !== '0') reasons.push(`send ${formatEgld(value)} EGLD to ${receiver}`)

  if (typeof tx.data === 'string' && tx.data.length > 0) {
    let decoded = ''
    try {
      decoded = Buffer.from(tx.data, 'base64').toString('utf8')
    } catch {
      decoded = ''
    }
    const fn = decoded.split('@')[0] ?? ''
    if (fn && TOKEN_TRANSFER_FUNCS.has(fn)) {
      reasons.push(`token transfer (${fn}) to ${receiver}`)
      level = maxLevel(level, 'low')
    } else if (fn) {
      reasons.push(`contract call ${fn}() on ${receiver}`)
      level = maxLevel(level, 'medium')
    }
  }

  if (reasons.length === 0) reasons.push(`MultiversX transaction to ${receiver}`)
  return { level, reasons, effectsExtracted: true }
}

export const multiversxDecoder: ChainDecoder = {
  family: 'MultiversX',
  decode: (payloadHex, kind) =>
    kind === 'message' ? messageSignature() : decodeMultiversX(payloadHex),
}
