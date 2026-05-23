import { describe, it, expect } from 'vitest'
import { cosmosDecoder } from './cosmos.js'

// ── Minimal protobuf encoders (mirror the wire format the decoder reads) ──────

function encodeVarint(n: number): number[] {
  const out: number[] = []
  let v = n
  while (v > 0x7f) {
    out.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  out.push(v)
  return out
}

/** field N, wire type 2 (length-delimited). */
function lenDelim(field: number, payload: number[]): number[] {
  const tag = (field << 3) | 2
  return [...encodeVarint(tag), ...encodeVarint(payload.length), ...payload]
}

function utf8(s: string): number[] {
  return [...new TextEncoder().encode(s)]
}

/** google.protobuf.Any { type_url = field1 } (value omitted — not read). */
function anyMsg(typeUrl: string): number[] {
  return lenDelim(1, utf8(typeUrl))
}

/** Build a TxRaw hex from a list of message type URLs. */
function buildTxRaw(typeUrls: string[]): string {
  const body: number[] = []
  for (const tu of typeUrls) body.push(...lenDelim(1, anyMsg(tu))) // TxBody.messages
  const txRaw = lenDelim(1, body) // TxRaw.body_bytes
  return `0x${Buffer.from(txRaw).toString('hex')}`
}

const ctx = { chainId: 'cosmos:cosmoshub-4', namespace: 'cosmos', reference: 'cosmoshub-4' }

describe('cosmosDecoder', () => {
  it('decodes a plain MsgSend as no-special-risk', () => {
    const r = cosmosDecoder.decode(buildTxRaw(['/cosmos.bank.v1beta1.MsgSend']), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('/cosmos.bank.v1beta1.MsgSend')
  })

  it('flags CosmWasm MsgExecuteContract as medium', () => {
    const r = cosmosDecoder.decode(
      buildTxRaw(['/cosmwasm.wasm.v1.MsgExecuteContract']),
      'transaction',
      ctx,
    )
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('medium')
  })

  it('flags an authz MsgGrant as high', () => {
    const r = cosmosDecoder.decode(buildTxRaw(['/cosmos.authz.v1beta1.MsgGrant']), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('high')
  })

  it('takes the max severity across multiple messages', () => {
    const r = cosmosDecoder.decode(
      buildTxRaw(['/cosmos.bank.v1beta1.MsgSend', '/cosmwasm.wasm.v1.MsgExecuteContract']),
      'transaction',
      ctx,
    )
    expect(r.level).toBe('medium')
    expect(r.reasons.length).toBe(2)
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = cosmosDecoder.decode('0xaabbccdd', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = cosmosDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
  })
})
