import { describe, it, expect } from 'vitest'
import { toRlp } from 'viem'
import { vechainDecoder } from './vechain.js'

const ctx = { chainId: 'vechain:100009', namespace: 'vechain', reference: '100009' }
const TO = '0x000000000000000000000000000000000000abcd'

type Clause = readonly [`0x${string}`, `0x${string}`, `0x${string}`]

function buildTx(clauses: Clause[]): string {
  // [chainTag, blockRef, expiration, clauses, gasPriceCoef, gas, dependsOn, nonce, reserved]
  const tx = [
    '0x4a',
    '0x0000000000000000',
    '0x20',
    clauses.map((c) => [c[0], c[1], c[2]]),
    '0x00',
    '0x82a410',
    '0x',
    '0x0000000000000000',
    [],
  ] as const
  return toRlp(tx as never, 'hex')
}

describe('vechainDecoder', () => {
  it('decodes a VET transfer clause', () => {
    const r = vechainDecoder.decode(buildTx([[TO, '0xde0b6b3a7640000', '0x']]), 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain(TO)
    expect(r.reasons.join(' ')).toContain('VET')
  })

  it('flags an unlimited token approval as high', () => {
    const data = (`0x095ea7b3${'0'.repeat(64)}${'f'.repeat(64)}`) as `0x${string}`
    const r = vechainDecoder.decode(buildTx([[TO, '0x', data]]), 'transaction', ctx)
    expect(r.level).toBe('high')
    expect(r.reasons.join(' ')).toContain('unlimited token approval')
  })

  it('flags setApprovalForAll as medium', () => {
    const data = (`0xa22cb465${'0'.repeat(64)}${'0'.repeat(63)}1`) as `0x${string}`
    const r = vechainDecoder.decode(buildTx([[TO, '0x', data]]), 'transaction', ctx)
    expect(r.level).toBe('medium')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = vechainDecoder.decode('0xc0ffee', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = vechainDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
