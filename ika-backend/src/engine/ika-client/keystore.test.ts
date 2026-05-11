import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'

// In-memory mock of the pg `query` used by the keystore: INSERT stores a row,
// UPDATE patches it by id, SELECT finds it by (owner_ref, dwallet_address).
const { rows, queryMock } = vi.hoisted(() => {
  const rows: Array<Record<string, unknown>> = []
  const queryMock = vi.fn(async (text: string, params: unknown[] = []) => {
    const t = text.trim().toUpperCase()
    const p = params as any[]
    if (t.startsWith('INSERT')) {
      // [id, owner_ref, curve, signer_pubkey, wrapped_key, wrap_iv, wrap_tag, kdf_salt, kdf_params]
      rows.push({
        id: p[0],
        owner_ref: p[1],
        curve: p[2],
        signer_pubkey: Buffer.from(p[3]),
        dwallet_public_key: null,
        wrapped_key: Buffer.from(p[4]),
        wrap_iv: Buffer.from(p[5]),
        wrap_tag: Buffer.from(p[6]),
        kdf_salt: Buffer.from(p[7]),
        kdf_params: typeof p[8] === 'string' ? JSON.parse(p[8]) : p[8],
        attestation_data: null,
        network_signature: null,
        network_pubkey: null,
        dwallet_address: null,
      })
      return { rows: [], rowCount: 1 }
    }
    if (t.startsWith('UPDATE')) {
      // [id, dwallet_address, dwallet_public_key, attestation_data, network_signature, network_pubkey]
      const r = rows.find((x) => x.id === p[0])
      if (r) {
        r.dwallet_address = p[1]
        r.dwallet_public_key = Buffer.from(p[2])
        r.attestation_data = Buffer.from(p[3])
        r.network_signature = Buffer.from(p[4])
        r.network_pubkey = Buffer.from(p[5])
      }
      return { rows: [], rowCount: r ? 1 : 0 }
    }
    if (t.startsWith('SELECT')) {
      // [owner_ref, dwallet_address]
      const r = rows.find((x) => x.owner_ref === p[0] && x.dwallet_address === p[1])
      return { rows: r ? [r] : [] }
    }
    return { rows: [] }
  })
  return { rows, queryMock }
})
vi.mock('../../store/pool.js', () => ({ query: queryMock }))

// Imported after the mock so the keystore picks up the mocked `query`.
const {
  createWrappedWalletKey,
  finalizeWalletKey,
  unwrapWalletKey,
  getWalletKeyMeta,
  WeakPassphraseError,
  WrongPassphraseError,
  WalletKeyNotFoundError,
} = await import('./keystore.js')

describe('ika-client/keystore — A2 passphrase-wrapped signer key', () => {
  beforeEach(() => {
    rows.length = 0
    queryMock.mockClear()
  })

  it('round-trips the Ed25519 signer key through wrap → finalize → unwrap', async () => {
    const passphrase = 'test-passphrase-1234'
    const created = await createWrappedWalletKey({ ownerRef: 'u1', passphrase, curve: 2 })
    expect(created.signerSecret.length).toBe(32)
    expect(created.signerPubkey.length).toBe(32)
    expect(Buffer.from(created.signerPubkey)).toEqual(Buffer.from(ed25519.getPublicKey(created.signerSecret)))

    const dwalletPublicKey = new Uint8Array(32).fill(7)
    await finalizeWalletKey({
      id: created.id,
      dwalletAddress: 'DW1',
      dwalletPublicKey,
      attestationData: new Uint8Array([1, 2, 3]),
      networkSignature: new Uint8Array(64).fill(9),
      networkPubkey: new Uint8Array(32).fill(5),
    })

    const unwrapped = await unwrapWalletKey({ ownerRef: 'u1', dwalletAddress: 'DW1', passphrase })
    expect(Buffer.from(unwrapped.signerSecret)).toEqual(Buffer.from(created.signerSecret))
    expect(Buffer.from(unwrapped.signerPubkey)).toEqual(Buffer.from(created.signerPubkey))
    expect(unwrapped.curve).toBe(2)
    expect(Buffer.from(unwrapped.dwalletPublicKey)).toEqual(Buffer.from(dwalletPublicKey))
    expect(Buffer.from(unwrapped.attestationData)).toEqual(Buffer.from(new Uint8Array([1, 2, 3])))

    const meta = await getWalletKeyMeta({ ownerRef: 'u1', dwalletAddress: 'DW1' })
    expect(Buffer.from(meta.signerPubkey)).toEqual(Buffer.from(created.signerPubkey))
    expect(Buffer.from(meta.dwalletPublicKey)).toEqual(Buffer.from(dwalletPublicKey))
  })

  it('rejects a wrong passphrase on unwrap (GCM tag mismatch)', async () => {
    const created = await createWrappedWalletKey({ ownerRef: 'u2', passphrase: 'correct-passphrase-1', curve: 2 })
    await finalizeWalletKey({
      id: created.id,
      dwalletAddress: 'DW2',
      dwalletPublicKey: new Uint8Array(32),
      attestationData: new Uint8Array([1]),
      networkSignature: new Uint8Array(64),
      networkPubkey: new Uint8Array(32),
    })
    await expect(
      unwrapWalletKey({ ownerRef: 'u2', dwalletAddress: 'DW2', passphrase: 'wrong-passphrase-99' }),
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rejects a passphrase shorter than 12 characters', async () => {
    await expect(createWrappedWalletKey({ ownerRef: 'u3', passphrase: 'short', curve: 2 })).rejects.toBeInstanceOf(
      WeakPassphraseError,
    )
    expect(rows).toHaveLength(0) // nothing was inserted
  })

  it('throws WalletKeyNotFoundError when no record matches', async () => {
    // Created but not finalized → dwallet_address is NULL → the SELECT misses.
    await createWrappedWalletKey({ ownerRef: 'u4', passphrase: 'test-passphrase-9876', curve: 2 })
    await expect(getWalletKeyMeta({ ownerRef: 'u4', dwalletAddress: 'DW4' })).rejects.toBeInstanceOf(
      WalletKeyNotFoundError,
    )
    await expect(
      unwrapWalletKey({ ownerRef: 'u4', dwalletAddress: 'DW4', passphrase: 'test-passphrase-9876' }),
    ).rejects.toBeInstanceOf(WalletKeyNotFoundError)
  })
})
