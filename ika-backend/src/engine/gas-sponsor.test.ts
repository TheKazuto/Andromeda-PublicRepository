import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  initGasSponsor,
  initGasSponsorPool,
  getGasSponsor,
  getGasSponsorAddress,
  getGasSponsorPoolAddresses,
} from './gas-sponsor.js'

// `signAndSendInstructions` needs a live Solana RPC, so this only covers the
// keypair-loading / config-validation surface, which is the part that runs at
// boot and gates whether the recovery layer can start at all.

function makeKeypairJson(seed: number): string {
  const secret = new Uint8Array(32).fill(seed)
  const pub = ed25519.getPublicKey(secret)
  return JSON.stringify([...secret, ...pub])
}

const secret = new Uint8Array(32).fill(13)
const pub = ed25519.getPublicKey(secret)
const validKeypairJson = JSON.stringify([...secret, ...pub]) // solana-keygen format: 32 secret + 32 public

describe('engine/gas-sponsor — keypair loading + validation', () => {
  it('getGasSponsor throws before initialization', () => {
    expect(() => getGasSponsor()).toThrow('Gas sponsor not initialized')
  })

  it('rejects non-JSON', async () => {
    await expect(initGasSponsor('not json at all')).rejects.toThrow('must be a JSON byte array')
  })

  it('rejects JSON that is not a byte array', async () => {
    await expect(initGasSponsor('"a string"')).rejects.toThrow('must be an array of bytes')
    await expect(initGasSponsor('{"a":1}')).rejects.toThrow('must be an array of bytes')
    await expect(initGasSponsor('[1, 2, "x"]')).rejects.toThrow('must be an array of bytes')
  })

  it('rejects a byte array of the wrong length', async () => {
    await expect(initGasSponsor('[1, 2, 3]')).rejects.toThrow('must be 64 bytes (got 3)')
    await expect(initGasSponsor(JSON.stringify(Array(32).fill(0)))).rejects.toThrow('must be 64 bytes (got 32)')
  })

  it('loads a valid 64-byte keypair and exposes its address', async () => {
    const signer = await initGasSponsor(validKeypairJson, { minBalanceSol: 1, maxGasPerOpLamports: 5_000_000 })
    expect(typeof signer.address).toBe('string')
    expect(getGasSponsorAddress()).toBe(signer.address)
  })
})

describe('engine/gas-sponsor — pool of N fee payers (P0.5 / refinement)', () => {
  it('initGasSponsorPool requires at least one keypair', async () => {
    await expect(initGasSponsorPool([])).rejects.toThrow('requires at least one keypair')
  })

  it('loads N distinct keypairs and exposes all addresses', async () => {
    const kps = [makeKeypairJson(1), makeKeypairJson(2), makeKeypairJson(3)]
    const signers = await initGasSponsorPool(kps)
    expect(signers).toHaveLength(3)
    const addrs = getGasSponsorPoolAddresses()
    expect(addrs).toHaveLength(3)
    // All addresses must be distinct.
    expect(new Set(addrs.map(String)).size).toBe(3)
    // Primary (index 0) is what getGasSponsor() returns.
    expect(String(getGasSponsor().address)).toBe(String(signers[0]!.address))
  })

  it('deduplicates keypairs by address (operator typo)', async () => {
    const kps = [makeKeypairJson(7), makeKeypairJson(7), makeKeypairJson(8)]
    const signers = await initGasSponsorPool(kps)
    // Two unique addresses survive.
    const unique = new Set(signers.map((s) => String(s.address)))
    expect(unique.size).toBe(2)
  })

  it('initGasSponsor() still works as a single-keypair shortcut', async () => {
    const single = await initGasSponsor(makeKeypairJson(99))
    expect(typeof single.address).toBe('string')
    // The pool collapses to a single entry; getGasSponsor returns it.
    expect(getGasSponsorPoolAddresses()).toHaveLength(1)
    expect(String(getGasSponsorAddress())).toBe(String(single.address))
  })

  it('rejects malformed keypair in the pool with same validation as single', async () => {
    await expect(initGasSponsorPool(['not json'])).rejects.toThrow('JSON byte array')
    await expect(initGasSponsorPool(['[1,2,3]'])).rejects.toThrow('must be 64 bytes')
  })
})
