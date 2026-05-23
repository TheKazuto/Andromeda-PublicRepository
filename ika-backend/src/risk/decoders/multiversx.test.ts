import { describe, it, expect } from 'vitest'
import { multiversxDecoder } from './multiversx.js'

const ctx = { chainId: 'mvx:1', namespace: 'mvx', reference: '1' }
const RCV = 'erd1qqqqqqqqqqqqqpgq0000000000000000000000000000000000000000000'

function txHex(tx: Record<string, unknown>): string {
  return `0x${Buffer.from(JSON.stringify(tx)).toString('hex')}`
}
function dataB64(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64')
}

describe('multiversxDecoder', () => {
  it('decodes a native EGLD transfer', () => {
    const r = multiversxDecoder.decode(
      txHex({ receiver: RCV, value: '1000000000000000000' }),
      'transaction',
      ctx,
    )
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('1 EGLD')
    expect(r.reasons.join(' ')).toContain(RCV)
  })

  it('flags an ESDT token transfer as low', () => {
    const r = multiversxDecoder.decode(
      txHex({ receiver: RCV, value: '0', data: dataB64('ESDTTransfer@544f4b454e@0a') }),
      'transaction',
      ctx,
    )
    expect(r.level).toBe('low')
    expect(r.reasons.join(' ')).toContain('ESDTTransfer')
  })

  it('flags an arbitrary contract call as medium', () => {
    const r = multiversxDecoder.decode(
      txHex({ receiver: RCV, value: '0', data: dataB64('swapTokensFixedInput@01') }),
      'transaction',
      ctx,
    )
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('swapTokensFixedInput')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = multiversxDecoder.decode('0xaabbcc', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = multiversxDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
