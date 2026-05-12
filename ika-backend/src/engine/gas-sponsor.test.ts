import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { initGasSponsor, getGasSponsor, getGasSponsorAddress } from './gas-sponsor.js'

// `signAndSendInstructions` needs a live Solana RPC, so this only covers the
// keypair-loading / config-validation surface, which is the part that runs at
// boot and gates whether the recovery layer can start at all.

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
