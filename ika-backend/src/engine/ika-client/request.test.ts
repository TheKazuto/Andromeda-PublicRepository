import { describe, it, expect, vi, beforeEach } from 'vitest'
import { defineBcsTypes } from './bcs.js'

// Mock the gRPC singleton: the engine high-level path is exercised against
// canned BCS responses, no real validator network.
const grpc = vi.hoisted(() => ({ submitTransaction: vi.fn(), getPresigns: vi.fn() }))
vi.mock('../grpc-client.js', () => ({
  getIkaGrpcClient: () => ({ submitTransaction: grpc.submitTransaction, getPresigns: grpc.getPresigns }),
}))

const { requestDkg, requestPresign, requestSign, deriveDwalletAddress } = await import('./request.js')

const T = defineBcsTypes()
const z = (n: number, fill = 0): number[] => Array.from(new Uint8Array(n).fill(fill))

function attestationResponse(innerAttestationData: number[]): Uint8Array {
  return T.TransactionResponseData.serialize({
    Attestation: {
      attestation_data: innerAttestationData,
      network_signature: z(64, 0xaa),
      network_pubkey: z(32, 0xbb),
      epoch: 1n,
    },
  }).toBytes()
}
function signatureResponse(sig: number[]): Uint8Array {
  return T.TransactionResponseData.serialize({ Signature: { signature: sig } }).toBytes()
}
function errorResponse(message: string): Uint8Array {
  return T.TransactionResponseData.serialize({ Error: { message } }).toBytes()
}
function reply(bytes: Uint8Array): void {
  grpc.submitTransaction.mockResolvedValueOnce({ response_data: bytes })
}

const SENDER = new Uint8Array(32).fill(7)

describe('engine/ika-client/request — high-level DKG / Presign / Sign', () => {
  beforeEach(() => {
    grpc.submitTransaction.mockReset()
    grpc.getPresigns.mockReset()
    grpc.getPresigns.mockResolvedValue([]) // epoch falls back to 1
  })

  it('requestDkg returns the dWallet public key + attestation parts from the network response', async () => {
    const dkgV1 = T.VersionedDWalletDataAttestation.serialize({
      V1: {
        session_identifier: z(32),
        intended_chain_sender: Array.from(SENDER),
        curve: { Curve25519: true },
        public_key: z(32, 0x42),
        public_output: [1, 2, 3],
        is_imported_key: false,
        sign_during_dkg_signature: null,
      },
    }).toBytes()
    reply(attestationResponse(Array.from(dkgV1)))

    const out = await requestDkg({ curve: 'Curve25519', senderPubkey: SENDER })
    expect(Array.from(out.publicKey)).toEqual(z(32, 0x42))
    expect(Array.from(out.publicOutput)).toEqual([1, 2, 3])
    expect(out.sessionPreimage).toHaveLength(32)
    expect(Array.from(out.networkSignature)).toEqual(z(64, 0xaa))
    expect(Array.from(out.networkPubkey)).toEqual(z(32, 0xbb))
    expect(out.attestationData).toEqual(dkgV1)
    // the payload we actually submitted carried a DKG request for this sender
    const sent = grpc.submitTransaction.mock.calls[0]![0] as { signed_request_data: Uint8Array }
    const parsedReq = T.SignedRequestData.parse(sent.signed_request_data) as any
    expect(parsedReq.request).toHaveProperty('DKG')
    expect(parsedReq.intended_chain_sender).toEqual(Array.from(SENDER))
  })

  it('requestDkg throws on an Error response', async () => {
    reply(errorResponse('dkg boom'))
    await expect(requestDkg({ curve: 'Curve25519', senderPubkey: SENDER })).rejects.toThrow('DKG rejected: dkg boom')
  })

  it('requestDkg throws if the network returns a signature instead of an attestation', async () => {
    reply(signatureResponse(z(64)))
    await expect(requestDkg({ curve: 'Curve25519', senderPubkey: SENDER })).rejects.toThrow('expected an attestation')
  })

  it('requestPresign returns the presign session identifier from the attestation', async () => {
    const psV1 = T.VersionedPresignDataAttestation.serialize({
      V1: {
        session_identifier: z(32),
        epoch: 1n,
        presign_session_identifier: [9, 9, 9],
        presign_data: [],
        curve: { Curve25519: true },
        signature_algorithm: { EdDSA: true },
        dwallet_public_key: null,
        user_pubkey: z(32),
      },
    }).toBytes()
    reply(attestationResponse(Array.from(psV1)))
    const id = await requestPresign({ curve: 'Curve25519', senderPubkey: SENDER })
    expect(Array.from(id)).toEqual([9, 9, 9])
  })

  it('requestPresign throws on an Error response', async () => {
    reply(errorResponse('presign nope'))
    await expect(requestPresign({ curve: 'Curve25519', senderPubkey: SENDER })).rejects.toThrow('Presign rejected: presign nope')
  })

  it('requestSign returns the raw signature on a Signature response', async () => {
    reply(signatureResponse([1, 2, 3, 4]))
    const sig = await requestSign({
      curve: 'Curve25519',
      senderPubkey: SENDER,
      message: new Uint8Array([0xde, 0xad]),
      presignSessionId: new Uint8Array([5, 5]),
      dwalletAttestationData: new Uint8Array(32),
      dwalletNetworkSignature: new Uint8Array(64),
      dwalletNetworkPubkey: new Uint8Array(32),
      approvalTxSignature: new Uint8Array(64),
      approvalSlot: 123n,
    })
    expect(Array.from(sig)).toEqual([1, 2, 3, 4])
    const sent = grpc.submitTransaction.mock.calls[0]![0] as { signed_request_data: Uint8Array }
    const parsedReq = T.SignedRequestData.parse(sent.signed_request_data) as any
    expect(parsedReq.request).toHaveProperty('Sign')
    expect(parsedReq.request.Sign.approval_proof).toHaveProperty('Solana')
    expect(BigInt(parsedReq.request.Sign.approval_proof.Solana.slot as string)).toBe(123n)
  })

  it('requestSign throws on an Error response and when the network returns an attestation', async () => {
    reply(errorResponse('sign rejected by policy'))
    await expect(
      requestSign({
        curve: 'Curve25519', senderPubkey: SENDER, message: new Uint8Array([1]),
        presignSessionId: new Uint8Array([1]), dwalletAttestationData: new Uint8Array(0),
        dwalletNetworkSignature: new Uint8Array(0), dwalletNetworkPubkey: new Uint8Array(0),
        approvalTxSignature: new Uint8Array(0), approvalSlot: 0n,
      }),
    ).rejects.toThrow('Sign rejected: sign rejected by policy')

    reply(attestationResponse([0]))
    await expect(
      requestSign({
        curve: 'Curve25519', senderPubkey: SENDER, message: new Uint8Array([1]),
        presignSessionId: new Uint8Array([1]), dwalletAttestationData: new Uint8Array(0),
        dwalletNetworkSignature: new Uint8Array(0), dwalletNetworkPubkey: new Uint8Array(0),
        approvalTxSignature: new Uint8Array(0), approvalSlot: 0n,
      }),
    ).rejects.toThrow('expected a signature')
  })

  it('rejects an empty network response', async () => {
    grpc.submitTransaction.mockResolvedValueOnce({ response_data: new Uint8Array(0) })
    await expect(requestDkg({ curve: 'Curve25519', senderPubkey: SENDER })).rejects.toThrow('empty response')
  })

  it('deriveDwalletAddress is deterministic for a (curve, pubkey, program) triple', async () => {
    const prog = '11111111111111111111111111111111' as never
    const a = await deriveDwalletAddress(2, new Uint8Array(32).fill(3), prog)
    const b = await deriveDwalletAddress(2, new Uint8Array(32).fill(3), prog)
    expect(a.address).toBe(b.address)
    const c = await deriveDwalletAddress(2, new Uint8Array(32).fill(4), prog)
    expect(c.address).not.toBe(a.address)
  })
})
