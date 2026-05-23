// VeChain (Thor) transaction decoder (advisory).
//
// A VeChain tx is RLP-encoded (decoded here with viem's `fromRlp`, already a
// dep). The unsigned body is a list whose 4th element is `clauses`, each clause
// being `[to, value, data]`. We surface per-clause recipients, VET amounts and
// EVM-style calldata heuristics (VeChain contract calls use Ethereum ABI).

import { fromRlp } from 'viem'
import type { CalldataRisk } from '../types.js'
import { maxLevel, messageSignature, unverifiable, type ChainDecoder } from './registry.js'

type RlpItem = string | readonly RlpItem[]

const MAX_UINT256_HEX = 'f'.repeat(64)

function asHex(item: RlpItem | undefined): string {
  return typeof item === 'string' ? item : '0x'
}

function hexToBigInt(h: string): bigint {
  return h && h !== '0x' ? BigInt(h) : 0n
}

function decodeVeChain(payloadHex: string): CalldataRisk {
  let clauses: readonly RlpItem[]
  try {
    const hex = (payloadHex.startsWith('0x') ? payloadHex : `0x${payloadHex}`) as `0x${string}`
    const decoded = fromRlp(hex, 'hex') as RlpItem
    // Unsigned tx: [chainTag, blockRef, expiration, clauses, gasPriceCoef, gas, dependsOn, nonce, reserved].
    if (!Array.isArray(decoded) || decoded.length < 4) throw new Error('not a VeChain tx')
    const c = decoded[3]
    if (!Array.isArray(c)) throw new Error('no clauses')
    clauses = c
  } catch {
    return unverifiable('failed to decode VeChain transaction; effects cannot be verified')
  }

  if (clauses.length === 0) {
    return unverifiable('VeChain tx: no clauses; effects cannot be verified')
  }

  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'

  for (const clause of clauses) {
    if (!Array.isArray(clause) || clause.length < 3) continue
    const to = asHex(clause[0])
    const dest = to && to !== '0x' ? to : '(contract creation)'
    const valWei = hexToBigInt(asHex(clause[1]))
    const data = asHex(clause[2])
    const calldata = (data.startsWith('0x') ? data.slice(2) : data).toLowerCase()

    if (valWei > 0n) reasons.push(`send ${valWei.toString()} wei VET to ${dest}`)

    if (calldata.length >= 8) {
      const selector = calldata.slice(0, 8)
      const args = calldata.slice(8)
      if (selector === '095ea7b3') {
        const amountHex = args.slice(64, 128)
        if (amountHex === MAX_UINT256_HEX) {
          reasons.push(`unlimited token approval to ${dest}`)
          level = maxLevel(level, 'high')
        } else {
          reasons.push(`token approval to ${dest}`)
          level = maxLevel(level, 'low')
        }
      } else if (selector === 'a22cb465') {
        reasons.push(`setApprovalForAll on ${dest}`)
        level = maxLevel(level, 'medium')
      } else {
        reasons.push(`contract call 0x${selector} on ${dest}`)
        level = maxLevel(level, 'low')
      }
    } else if (valWei === 0n) {
      reasons.push(`call to ${dest}`)
    }
  }

  if (reasons.length === 0) {
    return unverifiable('VeChain tx: clauses had no decodable effects; effects cannot be verified')
  }
  return { level, reasons, effectsExtracted: true }
}

export const vechainDecoder: ChainDecoder = {
  family: 'VeChain',
  decode: (payloadHex, kind) =>
    kind === 'message' ? messageSignature() : decodeVeChain(payloadHex),
}
