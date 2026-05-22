import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { preProcessForChain, type MessageKind } from './preprocess.js'
import { UnsupportedChainError, ChainIdParseError } from './errors.js'

interface PreprocessFixture {
  cases: Array<{
    chainId: string
    kind: MessageKind
    scheme: number
    payloadHex: string
    preprocessedHex: string
    digestHex: string | null
  }>
}

function findFixture(rel: string): string {
  let dir = resolve(import.meta.dirname)
  for (let i = 0; i < 12; i += 1) {
    const candidate = join(dir, 'fixtures', 'chain', rel)
    if (existsSync(candidate)) return candidate
    dir = resolve(dir, '..')
  }
  throw new Error(`fixtures/chain/${rel} not found above test file`)
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function toHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

const fixture = JSON.parse(readFileSync(findFixture('preprocess-v1.json'), 'utf8')) as PreprocessFixture

describe('preProcessForChain — parity with fixtures', () => {
  for (const c of fixture.cases) {
    it(`${c.chainId} (${c.kind}) matches the frozen envelope`, () => {
      const out = preProcessForChain(c.chainId, fromHex(c.payloadHex), c.kind)
      expect(toHex(out)).toBe(c.preprocessedHex)
    })
  }
})

describe('preProcessForChain — semantics', () => {
  it('leaves transaction bytes untouched for envelope-less chains', () => {
    const raw = fromHex('deadbeef')
    expect(preProcessForChain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', raw, 'transaction')).toEqual(raw)
    expect(preProcessForChain('cosmos:cosmoshub-4', raw, 'transaction')).toEqual(raw)
  })

  it('rejects unsupported and malformed chains (no silent raw fallback)', () => {
    expect(() => preProcessForChain('arweave:mainnet', new Uint8Array(1), 'message')).toThrow(UnsupportedChainError)
    expect(() => preProcessForChain('garbage', new Uint8Array(1), 'message')).toThrow(ChainIdParseError)
  })
})
