import { describe, it, expect } from 'vitest'
import { nearDecoder } from './near.js'

const ctx = { chainId: 'near:mainnet', namespace: 'near', reference: 'mainnet' }

// ── Borsh encoders ───────────────────────────────────────────────────────────

function u32le(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
}
function uNle(value: bigint, n: number): number[] {
  const out: number[] = []
  let v = value
  for (let i = 0; i < n; i += 1) {
    out.push(Number(v & 0xffn))
    v >>= 8n
  }
  return out
}
function str(s: string): number[] {
  const b = [...new TextEncoder().encode(s)]
  return [...u32le(b.length), ...b]
}

function buildTx(signer: string, receiver: string, actions: number[][]): string {
  const bytes: number[] = []
  bytes.push(...str(signer))
  bytes.push(0, ...new Array(32).fill(1)) // public_key: ED25519 + 32 bytes
  bytes.push(...uNle(1n, 8)) // nonce
  bytes.push(...str(receiver))
  bytes.push(...new Array(32).fill(2)) // block_hash
  bytes.push(...u32le(actions.length))
  for (const a of actions) bytes.push(...a)
  return `0x${Buffer.from(bytes).toString('hex')}`
}

const transferAction = (yocto: bigint): number[] => [3, ...uNle(yocto, 16)]
const functionCallAction = (method: string, deposit: bigint): number[] => [
  2,
  ...str(method),
  ...u32le(0), // args
  ...uNle(0n, 8), // gas
  ...uNle(deposit, 16), // deposit
]

describe('nearDecoder', () => {
  it('decodes a Transfer action', () => {
    const tx = buildTx('alice.near', 'bob.near', [transferAction(10n ** 24n)])
    const r = nearDecoder.decode(tx, 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('transfer 1 NEAR to bob.near')
  })

  it('flags a FunctionCall as medium', () => {
    const tx = buildTx('alice.near', 'contract.near', [functionCallAction('ft_transfer', 0n)])
    const r = nearDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('ft_transfer')
  })

  it('flags AddKey as high', () => {
    const tx = buildTx('alice.near', 'alice.near', [[5]])
    const r = nearDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('high')
    expect(r.reasons.join(' ')).toContain('access key')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = nearDecoder.decode('0xff', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = nearDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })
})
