// Cosmos SDK transaction decoder (advisory).
//
// Decodes a protobuf `TxRaw` far enough to enumerate the message type URLs in
// its `TxBody`. We don't decode message bodies — the type set is the advisory
// signal: a CosmWasm `MsgExecuteContract` or an authz `MsgGrant` is riskier than
// a plain `MsgSend`. Covers every `cosmos:*` chain (the wire format is shared).

import type { CalldataRisk } from '../types.js'
import {
  hexToBytes,
  maxLevel,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'
import { allFields, firstField, parseProtobuf } from './protobuf.js'

// Message type URLs that delegate authority or move value off the chain.
const HIGH_RISK_TYPES = new Set<string>([
  '/cosmos.authz.v1beta1.MsgGrant', // delegates send/exec authority to a grantee
  '/cosmos.authz.v1beta1.MsgExec', // executes pre-granted messages
  '/cosmos.feegrant.v1beta1.MsgGrantAllowance',
])

// Message type URLs that invoke arbitrary code or cross-chain transfers.
const MEDIUM_RISK_TYPES = new Set<string>([
  '/cosmwasm.wasm.v1.MsgExecuteContract',
  '/cosmwasm.wasm.v1.MsgMigrateContract',
  '/cosmwasm.wasm.v1.MsgInstantiateContract',
  '/cosmwasm.wasm.v1.MsgInstantiateContract2',
  '/ibc.applications.transfer.v1.MsgTransfer',
])

function decodeCosmos(payloadHex: string): CalldataRisk {
  let typeUrls: string[]
  try {
    const bytes = hexToBytes(payloadHex)
    if (bytes.length === 0) return unverifiable('empty Cosmos payload; effects cannot be verified')

    const txRaw = parseProtobuf(bytes)
    const bodyBytes = firstField(txRaw, 1)?.data // TxRaw.body_bytes
    if (!bodyBytes) return unverifiable('Cosmos tx: no TxBody found; effects cannot be verified')

    const body = parseProtobuf(bodyBytes)
    const messages = allFields(body, 1) // TxBody.messages (repeated Any)
      .map((f) => f.data)
      .filter((d): d is Uint8Array => d !== undefined)
    if (messages.length === 0) {
      return unverifiable('Cosmos tx: no messages found; effects cannot be verified')
    }

    typeUrls = []
    for (const m of messages) {
      const any = parseProtobuf(m)
      const tu = firstField(any, 1)?.data // Any.type_url (string)
      if (tu) typeUrls.push(new TextDecoder().decode(tu))
    }
  } catch {
    return unverifiable('failed to decode Cosmos transaction; effects cannot be verified')
  }

  if (typeUrls.length === 0) {
    return unverifiable('Cosmos tx: messages had no type URLs; effects cannot be verified')
  }

  const reasons: string[] = []
  let level: CalldataRisk['level'] = 'none'

  for (const tu of typeUrls) {
    if (HIGH_RISK_TYPES.has(tu)) {
      reasons.push(`high-risk Cosmos message ${tu} (delegates authority); verify the grantee`)
      level = maxLevel(level, 'high')
    } else if (MEDIUM_RISK_TYPES.has(tu)) {
      reasons.push(`Cosmos message ${tu}; verify the target contract/recipient`)
      level = maxLevel(level, 'medium')
    } else {
      reasons.push(`Cosmos message ${tu}`)
    }
  }

  return { level, reasons, effectsExtracted: true }
}

export const cosmosDecoder: ChainDecoder = {
  family: 'Cosmos',
  decode: (payloadHex, kind) => (kind === 'message' ? messageSignature() : decodeCosmos(payloadHex)),
}
