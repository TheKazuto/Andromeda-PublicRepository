import { describe, expect, it } from 'vitest'
import {
  parseChainId,
  resolveChainParams,
  isChainSupported,
  getSupportedChains,
  namespacesForCurve,
  SUPPORTED_NAMESPACES,
} from './chains.js'
import { ChainIdParseError, UnsupportedChainError } from './errors.js'

describe('parseChainId', () => {
  it('splits namespace and reference', () => {
    expect(parseChainId('eip155:1')).toEqual({ namespace: 'eip155', reference: '1' })
    expect(parseChainId('cosmos:cosmoshub-4')).toEqual({ namespace: 'cosmos', reference: 'cosmoshub-4' })
  })

  it('keeps a reference that itself contains a colon', () => {
    // CAIP-2 references can contain ":" — only the first one separates.
    expect(parseChainId('tron:0x2b:6653dc')).toEqual({ namespace: 'tron', reference: '0x2b:6653dc' })
  })

  it('rejects malformed ids', () => {
    expect(() => parseChainId('eip155')).toThrow(ChainIdParseError)
    expect(() => parseChainId(':1')).toThrow(ChainIdParseError)
    expect(() => parseChainId('eip155:')).toThrow(ChainIdParseError)
    expect(() => parseChainId('')).toThrow(ChainIdParseError)
  })
})

describe('resolveChainParams', () => {
  it('resolves the validated B1 families', () => {
    expect(resolveChainParams('eip155:8453')).toMatchObject({ namespace: 'eip155', curve: 'Secp256k1', scheme: 0 })
    expect(resolveChainParams('tron:0x2b6653dc')).toMatchObject({ curve: 'Secp256k1', scheme: 0 })
    expect(resolveChainParams('bip122:x')).toMatchObject({ curve: 'Secp256k1', scheme: 2 })
    expect(resolveChainParams('cosmos:cosmoshub-4')).toMatchObject({ curve: 'Secp256k1', scheme: 1 })
    expect(resolveChainParams('solana:x')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('sui:mainnet')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
  })

  it('resolves the B6/B7 families validated against official SDKs', () => {
    // Filecoin secp256k1 signs blake2b-256 → scheme 4 (not sha256).
    expect(resolveChainParams('fil:f')).toMatchObject({ curve: 'Secp256k1', scheme: 4 })
    expect(resolveChainParams('vechain:0x4a1208')).toMatchObject({ curve: 'Secp256k1', scheme: 4 })
    expect(resolveChainParams('avalanche:mainnet')).toMatchObject({ curve: 'Secp256k1', scheme: 1 })
    expect(resolveChainParams('casper:casper')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('tezos:mainnet')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('iota:iota')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('near:mainnet')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('polkadot:91b171bb158e2d3848fa23a9f1c25182')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('stellar:pubnet')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('algorand:x')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('aptos:1')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('mvx:1')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
    expect(resolveChainParams('ton:mainnet')).toMatchObject({ curve: 'Curve25519', scheme: 5 })
  })

  it('throws for unvalidated/unknown chains (no silent fallback)', () => {
    // Taproot deferred (Schnorr presign); XRPL signing hash unsupported; Arweave
    // (RSA) / StarkNet (Stark curve) are outside the Ika protocol — must NOT resolve.
    expect(() => resolveChainParams('xrpl:0')).toThrow(UnsupportedChainError)
    expect(() => resolveChainParams('arweave:mainnet')).toThrow(UnsupportedChainError)
    expect(() => resolveChainParams('starknet:SN_MAIN')).toThrow(UnsupportedChainError)
  })
})

describe('helpers', () => {
  it('isChainSupported does not throw', () => {
    expect(isChainSupported('eip155:1')).toBe(true)
    expect(isChainSupported('arweave:mainnet')).toBe(false)
    expect(isChainSupported('garbage')).toBe(false)
  })

  it('getSupportedChains returns every family', () => {
    const chains = getSupportedChains()
    expect(chains.map((c) => c.namespace).sort()).toEqual([...SUPPORTED_NAMESPACES].sort())
  })

  it('namespacesForCurve groups by curve', () => {
    expect(namespacesForCurve('Secp256k1').sort()).toEqual(['avalanche', 'bip122', 'cosmos', 'eip155', 'fil', 'tron', 'vechain'])
    expect(namespacesForCurve('Curve25519').sort()).toEqual(
      ['algorand', 'aptos', 'casper', 'iota', 'mvx', 'near', 'polkadot', 'solana', 'stellar', 'sui', 'tezos', 'ton'],
    )
    expect(namespacesForCurve('Secp256r1')).toEqual([])
  })
})
