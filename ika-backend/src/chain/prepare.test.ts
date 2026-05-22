import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { prepareMessage } from './prepare.js'
import { schemeDigest } from './digest.js'
import { type MessageKind } from './preprocess.js'
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

describe('prepareMessage — parity with fixtures', () => {
  for (const c of fixture.cases) {
    it(`${c.chainId} (${c.kind}) yields the frozen preprocessed + digest`, () => {
      const out = prepareMessage(c.chainId, fromHex(c.payloadHex), c.kind)
      expect(out.scheme).toBe(c.scheme)
      expect(out.preprocessedHex).toBe(c.preprocessedHex)
      expect(out.digestHex).toBe(c.digestHex)
    })
  }
})

describe('prepareMessage — semantics', () => {
  it('exposes curve + scheme for the chain', () => {
    expect(prepareMessage('eip155:1', fromHex('00'), 'transaction')).toMatchObject({ curve: 'Secp256k1', scheme: 0 })
    expect(prepareMessage('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', fromHex('00'), 'transaction')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
  })

  it('returns null digest for EdDSA chains (no simple pre-hash)', () => {
    expect(prepareMessage('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', fromHex('deadbeef'), 'transaction').digestHex).toBeNull()
  })

  it('throws on unsupported / malformed chains', () => {
    expect(() => prepareMessage('arweave:mainnet', fromHex('00'), 'message')).toThrow(UnsupportedChainError)
    expect(() => prepareMessage('garbage', fromHex('00'), 'message')).toThrow(ChainIdParseError)
  })
})

describe('schemeDigest', () => {
  const msg = fromHex('48656c6c6f')
  it('keccak256 for scheme 0, sha256 for 1, double-sha256 for 2', () => {
    expect(toHex(schemeDigest(0, msg)!).length).toBe(64)
    expect(toHex(schemeDigest(1, msg)!).length).toBe(64)
    // double-sha256 == sha256(sha256)
    expect(schemeDigest(2, msg)).toEqual(schemeDigest(1, schemeDigest(1, msg)!))
  })
  it('null for EdDSA / unknown schemes', () => {
    expect(schemeDigest(5, msg)).toBeNull()
    expect(schemeDigest(99, msg)).toBeNull()
  })
})
