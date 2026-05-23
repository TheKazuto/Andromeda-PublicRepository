import { describe, it, expect } from 'vitest'
import { algorandDecoder } from './algorand.js'

const ctx = { chainId: 'algorand:mainnet', namespace: 'algorand', reference: 'mainnet' }

// ── msgpack encoders ─────────────────────────────────────────────────────────

function fixstr(s: string): number[] {
  const b = [...new TextEncoder().encode(s)]
  return [0xa0 | b.length, ...b]
}
function bin(bytes: number[]): number[] {
  return [0xc4, bytes.length, ...bytes]
}
function uint32(n: number): number[] {
  return [0xce, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
}
function map(entries: [number[], number[]][]): number[] {
  const out: number[] = [0x80 | entries.length]
  for (const [k, v] of entries) out.push(...k, ...v)
  return out
}
function toHex(bytes: number[]): string {
  return `0x${Buffer.from(bytes).toString('hex')}`
}

const RCV = new Array(32).fill(0xab)

describe('algorandDecoder', () => {
  it('decodes a payment transaction', () => {
    const tx = map([
      [fixstr('type'), fixstr('pay')],
      [fixstr('rcv'), bin(RCV)],
      [fixstr('amt'), uint32(1_000_000)],
    ])
    const r = algorandDecoder.decode(toHex(tx), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('1 ALGO')
  })

  it('skips the optional "TX" signing prefix', () => {
    const tx = map([
      [fixstr('type'), fixstr('pay')],
      [fixstr('rcv'), bin(RCV)],
      [fixstr('amt'), uint32(500_000)],
    ])
    const withPrefix = [0x54, 0x58, ...tx] // "TX" + msgpack
    const r = algorandDecoder.decode(toHex(withPrefix), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.reasons.join(' ')).toContain('0.5 ALGO')
  })

  it('flags an application call as medium', () => {
    const tx = map([
      [fixstr('type'), fixstr('appl')],
      [fixstr('apid'), uint32(123)],
    ])
    const r = algorandDecoder.decode(toHex(tx), 'transaction', ctx)
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('app 123')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = algorandDecoder.decode('0xff00ff', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = algorandDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
