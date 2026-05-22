import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { deriveAddress, deriveAccountsForCurve } from './address.js'
import { InvalidPublicKeyError, UnsupportedChainError, ChainIdParseError } from './errors.js'

interface AddressFixture {
  keys: {
    secp256k1: { compressedHex: string; uncompressedHex: string }
    ed25519: { publicHex: string }
  }
  addresses: Array<{ chainId: string; curve: string; address: string; type?: string }>
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

const fixture = JSON.parse(readFileSync(findFixture('address-v1.json'), 'utf8')) as AddressFixture
const secpKey = fromHex(fixture.keys.secp256k1.compressedHex)
const secpUncompressed = fromHex(fixture.keys.secp256k1.uncompressedHex)
const edKey = fromHex(fixture.keys.ed25519.publicHex)

describe('deriveAddress — parity with fixtures', () => {
  for (const expected of fixture.addresses) {
    // Multi-format entries (e.g. Bitcoin p2pkh) are checked via deriveAccountsForCurve below.
    if (expected.type) continue
    it(`${expected.chainId} matches the frozen vector`, () => {
      const key = expected.curve === 'Secp256k1' ? secpKey : edKey
      expect(deriveAddress(key, expected.chainId)).toBe(expected.address)
    })
  }

  it('accepts an uncompressed secp256k1 key too (same result)', () => {
    const evm = fixture.addresses.find((a) => a.chainId === 'eip155:1')!
    expect(deriveAddress(secpUncompressed, 'eip155:1')).toBe(evm.address)
  })
})

describe('deriveAccountsForCurve', () => {
  it('Secp256k1 yields EVM / Bitcoin / Cosmos / Tron / Filecoin', () => {
    const accounts = deriveAccountsForCurve(secpKey, 'Secp256k1')
    const byNamespace = Object.fromEntries(accounts.map((a) => [a.chainId.split(':')[0], a.address]))
    expect(Object.keys(byNamespace).sort()).toEqual(
      ['avalanche', 'bip122', 'cosmos', 'eip155', 'fil', 'tron', 'vechain'],
    )
    expect(byNamespace.eip155).toBe('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
  })

  it('exposes both Bitcoin formats (segwit P2WPKH + legacy P2PKH)', () => {
    const accounts = deriveAccountsForCurve(secpKey, 'Secp256k1')
    const btc = accounts.filter((a) => a.chainId.startsWith('bip122:'))
    const byType = Object.fromEntries(btc.map((a) => [a.type, a.address]))
    expect(byType.p2wpkh).toMatch(/^bc1q/)
    const p2pkhExpected = fixture.addresses.find((a) => a.type === 'p2pkh')!
    expect(byType.p2pkh).toBe(p2pkhExpected.address)
    expect(byType.p2pkh).toMatch(/^1/)
  })

  it('Curve25519 yields Solana / Sui / Stellar / Algorand / Aptos / MultiversX', () => {
    const accounts = deriveAccountsForCurve(edKey, 'Curve25519')
    expect(accounts.map((a) => a.chainId.split(':')[0]).sort()).toEqual(
      ['algorand', 'aptos', 'casper', 'iota', 'mvx', 'near', 'polkadot', 'solana', 'stellar', 'sui', 'tezos', 'ton'],
    )
  })

  it('returns nothing for curves without B1 address derivation', () => {
    expect(deriveAccountsForCurve(secpKey, 'Secp256r1')).toEqual([])
  })
})

describe('deriveAddress — input validation', () => {
  it('rejects a wrong-length secp256k1 key', () => {
    expect(() => deriveAddress(new Uint8Array(32), 'eip155:1')).toThrow(InvalidPublicKeyError)
  })

  it('rejects a wrong-length ed25519 key', () => {
    expect(() => deriveAddress(new Uint8Array(33), 'solana:x')).toThrow(InvalidPublicKeyError)
  })

  it('rejects unsupported and malformed chains', () => {
    expect(() => deriveAddress(secpKey, 'arweave:mainnet')).toThrow(UnsupportedChainError)
    expect(() => deriveAddress(secpKey, 'nope')).toThrow(ChainIdParseError)
  })
})
