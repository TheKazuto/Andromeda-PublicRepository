// Aptos transaction decoder (advisory).
//
// An Aptos `RawTransaction` is BCS-encoded:
//   sender:address(32), sequence_number:u64, payload:TransactionPayload,
//   max_gas_amount:u64, gas_unit_price:u64, expiration_timestamp_secs:u64,
//   chain_id:u8
// We decode only as far as the payload's entry-function id (module::function) —
// enough for the advisory signal — and skip the recursive TypeTag/arg modelling.

import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'
import { ByteReader } from './bytereader.js'

// Entry functions that are plain coin transfers — low-noise, no special risk.
const TRANSFER_FUNCTIONS = new Set<string>([
  '0x1::coin::transfer',
  '0x1::aptos_account::transfer',
  '0x1::aptos_account::transfer_coins',
  '0x1::primary_fungible_store::transfer',
])

function decodeAptos(payloadHex: string): CalldataRisk {
  try {
    const r = new ByteReader(hexToBytes(payloadHex))
    if (r.remaining === 0) return unverifiable('empty Aptos payload; effects cannot be verified')

    r.fixed(32) // sender
    r.u64le() // sequence_number

    const payloadKind = r.uleb() // TransactionPayload enum
    if (payloadKind === 0) {
      return {
        level: 'high',
        reasons: ['Aptos Script payload (arbitrary bytecode); effects cannot be fully verified'],
        effectsExtracted: true,
      }
    }
    if (payloadKind !== 2) {
      // 1 = ModuleBundle (deprecated), 3 = Multisig, etc.
      return {
        level: 'medium',
        reasons: [`Aptos transaction payload type ${payloadKind}; verify before signing`],
        effectsExtracted: true,
      }
    }

    // EntryFunction { module: { address(32), name }, function, ty_args, args }
    const moduleAddrRaw = r.hex(32)
    const moduleAddr = `0x${moduleAddrRaw.replace(/^0+/, '') || '0'}`
    const moduleName = r.bcsString()
    const functionName = r.bcsString()
    const fqid = `${moduleAddr}::${moduleName}::${functionName}`

    if (TRANSFER_FUNCTIONS.has(fqid)) {
      return { level: 'none', reasons: [`Aptos coin transfer (${fqid})`], effectsExtracted: true }
    }
    return {
      level: maxLevel('none', 'medium'),
      reasons: [`Aptos entry function ${fqid}; verify the target module`],
      effectsExtracted: true,
    }
  } catch {
    return unverifiable('failed to decode Aptos transaction; effects cannot be verified')
  }
}

export const aptosDecoder: ChainDecoder = {
  family: 'Aptos',
  decode: (payloadHex, kind) => (kind === 'message' ? messageSignature() : decodeAptos(payloadHex)),
}
