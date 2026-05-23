import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { keccak_256 } from '@noble/hashes/sha3.js'
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

  it('returns keccak256 digest for EdDSA chains (the MessageApproval key)', () => {
    const out = prepareMessage('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', fromHex('deadbeef'), 'transaction')
    expect(out.digestHex).not.toBeNull()
    expect(out.digestHex).toBe(toHex(keccak_256(fromHex(out.preprocessedHex))))
  })

  it('throws on unsupported / malformed chains', () => {
    expect(() => prepareMessage('arweave:mainnet', fromHex('00'), 'message')).toThrow(UnsupportedChainError)
    expect(() => prepareMessage('garbage', fromHex('00'), 'message')).toThrow(ChainIdParseError)
  })
})

describe('schemeDigest', () => {
  const msg = fromHex('48656c6c6f')
  it('keccak256 for every supported scheme (the MessageApproval key)', () => {
    // Update 6 M1-fix: the approval digest is keccak256(message) for ALL
    // schemes; the scheme hash is applied by the network at sign time.
    const expected = keccak_256(msg)
    for (const scheme of [0, 1, 2, 3, 4, 5, 6]) {
      expect(schemeDigest(scheme, msg)).toEqual(expected)
    }
  })
  it('null for unknown schemes', () => {
    expect(schemeDigest(99, msg)).toBeNull()
  })
})
