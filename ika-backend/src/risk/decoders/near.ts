// NEAR transaction decoder (advisory).
//
// A NEAR `Transaction` is Borsh-encoded:
//   signer_id: string, public_key: {key_type:u8, data:[32|64]}, nonce:u64,
//   receiver_id: string, block_hash:[32], actions: Vec<Action>
// We enumerate the actions (Transfer, FunctionCall, AddKey, …) — the action set
// is the advisory signal (a FunctionCall or AddKey is riskier than a Transfer).

import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'
import { ByteReader } from './bytereader.js'

// 1 NEAR = 10^24 yoctoNEAR.
function formatNear(yocto: bigint): string {
  const whole = yocto / 10n ** 24n
  const frac = (yocto % 10n ** 24n).toString().padStart(24, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

function skipPublicKey(r: ByteReader): void {
  const keyType = r.u8()
  if (keyType === 0) r.fixed(32) // ED25519
  else if (keyType === 1) r.fixed(64) // SECP256K1
  else throw new Error('unknown NEAR key type')
}

function decodeNear(payloadHex: string): CalldataRisk {
  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'
  let receiver = ''
  try {
    const r = new ByteReader(hexToBytes(payloadHex))
    if (r.remaining === 0) return unverifiable('empty NEAR payload; effects cannot be verified')

    r.borshString() // signer_id
    skipPublicKey(r) // public_key
    r.u64le() // nonce
    receiver = r.borshString() // receiver_id
    r.fixed(32) // block_hash

    const actionCount = r.u32le()
    if (actionCount === 0 || actionCount > 1000) throw new Error('implausible action count')

    for (let i = 0; i < actionCount; i += 1) {
      const disc = r.u8()
      switch (disc) {
        case 0: // CreateAccount
          reasons.push(`create account ${receiver}`)
          level = maxLevel(level, 'low')
          break
        case 1: {
          // DeployContract { code: Vec<u8> }
          const len = r.u32le()
          r.fixed(len)
          reasons.push(`deploy contract code to ${receiver}`)
          level = maxLevel(level, 'high')
          break
        }
        case 2: {
          // FunctionCall { method_name, args, gas, deposit }
          const method = r.borshString()
          const argsLen = r.u32le()
          r.fixed(argsLen)
          r.u64le() // gas
          const deposit = r.u128le()
          reasons.push(
            `call ${method}() on ${receiver}${deposit > 0n ? ` with ${formatNear(deposit)} NEAR` : ''}`,
          )
          level = maxLevel(level, 'medium')
          break
        }
        case 3: {
          // Transfer { deposit: u128 }
          const deposit = r.u128le()
          reasons.push(`transfer ${formatNear(deposit)} NEAR to ${receiver}`)
          break
        }
        case 4: {
          // Stake { stake: u128, public_key }
          r.u128le()
          skipPublicKey(r)
          reasons.push(`stake on ${receiver}`)
          level = maxLevel(level, 'low')
          break
        }
        case 7: {
          // DeleteAccount { beneficiary_id: string }
          const beneficiary = r.borshString()
          reasons.push(`delete account ${receiver}, beneficiary ${beneficiary}`)
          level = maxLevel(level, 'high')
          break
        }
        case 5: // AddKey — access-key permission layout is complex; flag and stop.
          reasons.push(`add access key on ${receiver} (grants signing authority)`)
          level = maxLevel(level, 'high')
          return { level, reasons: [...reasons, 'remaining actions not decoded'], effectsExtracted: true }
        case 6: // DeleteKey
          reasons.push(`delete access key on ${receiver}`)
          level = maxLevel(level, 'high')
          return { level, reasons: [...reasons, 'remaining actions not decoded'], effectsExtracted: true }
        default:
          // Delegate (8) or unknown — can't reliably skip; report what we have.
          reasons.push(`additional NEAR action (type ${disc}) not decoded`)
          level = maxLevel(level, 'medium')
          return { level, reasons, effectsExtracted: true }
      }
    }
  } catch {
    if (reasons.length === 0) {
      return unverifiable('failed to decode NEAR transaction; effects cannot be verified')
    }
    // Partial decode is still useful for advisory.
    return { level, reasons: [...reasons, 'transaction partially decoded'], effectsExtracted: true }
  }

  if (reasons.length === 0) {
    return unverifiable('NEAR tx: no actions; effects cannot be verified')
  }
  return { level, reasons, effectsExtracted: true }
}

export const nearDecoder: ChainDecoder = {
  family: 'NEAR',
  decode: (payloadHex, kind) => (kind === 'message' ? messageSignature() : decodeNear(payloadHex)),
}
