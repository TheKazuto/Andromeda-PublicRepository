import { describe, it, expect } from 'vitest'
import { aptosDecoder } from './aptos.js'

const ctx = { chainId: 'aptos:1', namespace: 'aptos', reference: '1' }

// ── BCS encoders ─────────────────────────────────────────────────────────────

function uleb(n: number): number[] {
  const out: number[] = []
  let v = n
  while (v > 0x7f) {
    out.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  out.push(v)
  return out
}
function u64le(n: bigint): number[] {
  const out: number[] = []
  let v = n
  for (let i = 0; i < 8; i += 1) {
    out.push(Number(v & 0xffn))
    v >>= 8n
  }
  return out
}
function bcsStr(s: string): number[] {
  const b = [...new TextEncoder().encode(s)]
  return [...uleb(b.length), ...b]
}
function address(hexNoPrefix: string): number[] {
  return [...Buffer.from(hexNoPrefix.padStart(64, '0'), 'hex')]
}

function buildEntryFunction(moduleAddr: string, moduleName: string, fn: string): string {
  const bytes: number[] = []
  bytes.push(...address('00')) // sender
  bytes.push(...u64le(0n)) // sequence_number
  bytes.push(...uleb(2)) // payload = EntryFunction
  bytes.push(...address(moduleAddr)) // module address
  bytes.push(...bcsStr(moduleName)) // module name
  bytes.push(...bcsStr(fn)) // function name
  bytes.push(...uleb(0)) // ty_args
  bytes.push(...uleb(0)) // args
  bytes.push(...u64le(100n), ...u64le(100n), ...u64le(0n), 1) // gas/price/exp/chain_id
  return `0x${Buffer.from(bytes).toString('hex')}`
}

describe('aptosDecoder', () => {
  it('decodes a coin transfer entry function as no-special-risk', () => {
    const r = aptosDecoder.decode(buildEntryFunction('1', 'coin', 'transfer'), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('0x1::coin::transfer')
  })

  it('flags an arbitrary entry function as medium', () => {
    const r = aptosDecoder.decode(
      buildEntryFunction('abc', 'router', 'swap'),
      'transaction',
      ctx,
    )
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('::router::swap')
  })

  it('flags a Script payload as high', () => {
    // sender + seq + payload kind 0 (Script)
    const bytes = [...address('00'), ...u64le(0n), ...uleb(0)]
    const r = aptosDecoder.decode(`0x${Buffer.from(bytes).toString('hex')}`, 'transaction', ctx)
    expect(r.level).toBe('high')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = aptosDecoder.decode('0x00', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = aptosDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
