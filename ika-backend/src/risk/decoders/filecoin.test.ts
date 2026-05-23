import { describe, it, expect } from 'vitest'
import { filecoinDecoder } from './filecoin.js'

const ctx = { chainId: 'fil:f', namespace: 'fil', reference: 'f' }

// ── CBOR encoders ────────────────────────────────────────────────────────────

function cuint(n: number): number[] {
  if (n < 24) return [n]
  if (n < 256) return [0x18, n]
  return [0x19, (n >> 8) & 0xff, n & 0xff]
}
function cbytes(b: number[]): number[] {
  const len = b.length
  if (len < 24) return [0x40 | len, ...b]
  return [0x58, len, ...b]
}
function carrayHeader(n: number): number[] {
  return n < 24 ? [0x80 | n] : [0x98, n]
}

// secp256k1 address: protocol 1 + 20-byte payload.
const TO = [0x01, ...new Array(20).fill(0xab)]
// 1 FIL = 1e18 attoFIL = 0x0de0b6b3a7640000; value bytes = sign(0) + BE magnitude.
const ONE_FIL = [0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]

function buildMessage(valueBytes: number[], method: number): string {
  const msg = [
    ...carrayHeader(10),
    ...cuint(0), // version
    ...cbytes(TO), // to
    ...cbytes(TO), // from
    ...cuint(0), // nonce
    ...cbytes(valueBytes), // value
    ...cuint(10), // gasLimit
    ...cbytes([]), // gasFeeCap
    ...cbytes([]), // gasPremium
    ...cuint(method), // method
    ...cbytes([]), // params
  ]
  return `0x${Buffer.from(msg).toString('hex')}`
}

describe('filecoinDecoder', () => {
  it('decodes a FIL transfer with a derived f1 address', () => {
    const r = filecoinDecoder.decode(buildMessage(ONE_FIL, 0), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('1 FIL')
    expect(r.reasons.join(' ')).toMatch(/transfer 1 FIL to f1[a-z2-7]+/)
  })

  it('flags an actor method call as medium', () => {
    const r = filecoinDecoder.decode(buildMessage(ONE_FIL, 16), 'transaction', ctx)
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('actor method 16')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = filecoinDecoder.decode('0xff', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = filecoinDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
