import { describe, it, expect, vi, beforeEach } from 'vitest'
import bs58 from 'bs58'
import { defineBcsTypes } from './ika-client/bcs.js'

// `prepareDkg` resolves the Ika epoch via the gRPC client — mock it.
const { resolveEpoch } = vi.hoisted(() => ({ resolveEpoch: vi.fn() }))
vi.mock('./ika-client/request.js', () => ({ resolveEpoch }))

const { prepareDkg } = await import('./dkg.js')

const T = defineBcsTypes()
const SENDER = new Uint8Array(32).map((_, i) => i + 1)
const SENDER_B58 = bs58.encode(SENDER)

describe('engine/dkg — prepareDkg', () => {
  beforeEach(() => {
    resolveEpoch.mockReset()
    resolveEpoch.mockResolvedValue(7n)
  })

  it('builds a BCS SignedRequestData carrying the DKG request, sender, curve and epoch', async () => {
    const out = await prepareDkg({ curve: 'Curve25519', userPublicKeyBase58: SENDER_B58 })
    expect(out.curve).toBe('Curve25519')
    expect(out.curveId).toBe(2)
    expect(out.epoch).toBe('7')
    expect(out.intendedChainSenderBase58).toBe(SENDER_B58)

    const bytes = Uint8Array.from(Buffer.from(out.signedRequestDataBase64, 'base64'))
    const parsed = T.SignedRequestData.parse(bytes) as any
    expect(BigInt(parsed.epoch as string)).toBe(7n)
    expect(parsed.chain_id).toHaveProperty('Solana')
    expect(parsed.intended_chain_sender).toEqual(Array.from(SENDER))
    expect(parsed.request).toHaveProperty('DKG')
    expect(parsed.request.DKG.curve).toHaveProperty('Curve25519')
    expect(parsed.request.DKG.user_secret_key_share).toHaveProperty('Encrypted')
    expect(parsed.request.DKG.user_secret_key_share.Encrypted.signer_public_key).toEqual(Array.from(SENDER))
    expect(parsed.request.DKG.sign_during_dkg_request).toBeNull()

    // session preimage echoed back matches what's in the payload
    const preimage = Array.from(Uint8Array.from(Buffer.from(out.sessionPreimageBase64, 'base64')))
    expect(parsed.session_identifier_preimage).toEqual(preimage)
    expect(preimage).toHaveLength(32)
  })

  it('uses a fresh session preimage per call', async () => {
    const a = await prepareDkg({ curve: 'Secp256k1', userPublicKeyBase58: SENDER_B58 })
    const b = await prepareDkg({ curve: 'Secp256k1', userPublicKeyBase58: SENDER_B58 })
    expect(a.sessionPreimageBase64).not.toBe(b.sessionPreimageBase64)
  })

  it('rejects a malformed signer pubkey', async () => {
    await expect(prepareDkg({ curve: 'Secp256k1', userPublicKeyBase58: '0OIl-not-base58' })).rejects.toThrow(
      'Invalid userPublicKeyBase58',
    )
  })

  it('rejects a base58 string that is not 32 bytes', async () => {
    await expect(prepareDkg({ curve: 'Secp256k1', userPublicKeyBase58: bs58.encode(new Uint8Array(16)) })).rejects.toThrow(
      'Invalid userPublicKeyBase58',
    )
  })
})
