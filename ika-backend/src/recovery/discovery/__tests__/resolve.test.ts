import { describe, it, expect, vi, beforeEach } from 'vitest'
import bs58 from 'bs58'

// Mock the Postgres-backed store and the verifier registry so the flow is
// exercised in isolation (no DB, no real crypto).
const mocks = vi.hoisted(() => ({
  consumeChallenge: vi.fn(),
  findManagedDwalletsByPrimaryOwner: vi.fn(),
  insertChallenge: vi.fn(),
  verify: vi.fn(),
}))

vi.mock('../../store.js', () => ({
  consumeChallenge: mocks.consumeChallenge,
  findManagedDwalletsByPrimaryOwner: mocks.findManagedDwalletsByPrimaryOwner,
  insertChallenge: mocks.insertChallenge,
}))

vi.mock('../../verifiers/index.js', () => ({
  isKnownScheme: () => true,
  getVerifier: () => ({ scheme: 'ed25519-raw', verify: mocks.verify }),
}))

const { resolveChallenge } = await import('../flows.js')

const SOLANA_PUBKEY_B58 = bs58.encode(new Uint8Array(32).fill(7)) // 32-byte → Ed25519 primary
const DWALLET_A = bs58.encode(new Uint8Array(32).fill(11))
const DWALLET_B = bs58.encode(new Uint8Array(32).fill(12))

function challengeRow(over: Partial<Record<string, unknown>> = {}) {
  return {
    nonce: 'n1',
    app_id: 'app',
    scheme: 'ed25519-raw',
    wallet_address: SOLANA_PUBKEY_B58,
    message: 'msg',
    expires_at: new Date(Date.now() + 60_000),
    consumed_at: null,
    created_at: new Date(),
    ...over,
  }
}

describe('recovery/discovery — resolveChallenge', () => {
  beforeEach(() => {
    mocks.consumeChallenge.mockReset()
    mocks.findManagedDwalletsByPrimaryOwner.mockReset()
    mocks.verify.mockReset()
  })

  it('rejects an expired / unknown challenge', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(null)
    await expect(resolveChallenge({ nonce: 'n1', signature: 'sig' })).rejects.toThrow('Recovery challenge expired')
  })

  it('rejects an invalid signature', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow())
    mocks.verify.mockResolvedValueOnce(false)
    await expect(resolveChallenge({ nonce: 'n1', signature: 'sig' })).rejects.toThrow('Invalid signature')
  })

  it('enumerates managed dWallets for a 32-byte Ed25519 primary owner', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow())
    mocks.verify.mockResolvedValueOnce(true)
    mocks.findManagedDwalletsByPrimaryOwner.mockResolvedValueOnce([DWALLET_A, DWALLET_B])

    const out = await resolveChallenge({ nonce: 'n1', signature: 'sig' })
    expect(mocks.findManagedDwalletsByPrimaryOwner).toHaveBeenCalledWith({
      primaryScheme: 0,
      primaryIdentifier: expect.any(Uint8Array),
    })
    expect(out.dwallets).toEqual([DWALLET_A, DWALLET_B])
    expect(out.warnings).toHaveLength(0)
  })

  it('maps a 20-byte EVM address to a Secp256k1 primary owner', async () => {
    const evm = '0x' + 'ab'.repeat(20)
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow({ wallet_address: evm, scheme: 'secp256k1-eip191' }))
    mocks.verify.mockResolvedValueOnce(true)
    mocks.findManagedDwalletsByPrimaryOwner.mockResolvedValueOnce([DWALLET_A])

    const out = await resolveChallenge({ nonce: 'n1', signature: 'sig' })
    expect(mocks.findManagedDwalletsByPrimaryOwner).toHaveBeenCalledWith({
      primaryScheme: 1,
      primaryIdentifier: expect.any(Uint8Array),
    })
    expect(out.dwallets).toEqual([DWALLET_A])
  })

  it('warns and returns [] when the address format is not auto-mappable and no dwalletAddress is given', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow({ wallet_address: 'alice.near', scheme: 'ed25519-near' }))
    mocks.verify.mockResolvedValueOnce(true)

    const out = await resolveChallenge({ nonce: 'n1', signature: 'sig' })
    expect(mocks.findManagedDwalletsByPrimaryOwner).not.toHaveBeenCalled()
    expect(out.dwallets).toEqual([])
    expect(out.warnings.some((w) => w.includes('not auto-mappable'))).toBe(true)
    expect(out.warnings.some((w) => w.includes('no Andromeda-managed dWallet found'))).toBe(true)
  })

  it('confirms an explicitly supplied dwalletAddress', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow({ wallet_address: 'cosmos1xyz', scheme: 'secp256k1-adr036' }))
    mocks.verify.mockResolvedValueOnce(true)

    const out = await resolveChallenge({ nonce: 'n1', signature: 'sig', dwalletAddress: DWALLET_A })
    expect(out.dwallets).toEqual([DWALLET_A])
    expect(out.warnings.some((w) => w.includes('supplied by the caller'))).toBe(true)
  })

  it('rejects an invalid dwalletAddress', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow())
    mocks.verify.mockResolvedValueOnce(true)
    mocks.findManagedDwalletsByPrimaryOwner.mockResolvedValueOnce([])
    await expect(resolveChallenge({ nonce: 'n1', signature: 'sig', dwalletAddress: 'not-a-real-address' })).rejects.toThrow(
      'Invalid dwalletAddress',
    )
  })

  it('dedups an explicit dwalletAddress already present in the managed set', async () => {
    mocks.consumeChallenge.mockResolvedValueOnce(challengeRow())
    mocks.verify.mockResolvedValueOnce(true)
    mocks.findManagedDwalletsByPrimaryOwner.mockResolvedValueOnce([DWALLET_A])

    const out = await resolveChallenge({ nonce: 'n1', signature: 'sig', dwalletAddress: DWALLET_A })
    expect(out.dwallets).toEqual([DWALLET_A])
    expect(out.warnings.some((w) => w.includes('supplied by the caller'))).toBe(false)
  })
})
