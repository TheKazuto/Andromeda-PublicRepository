import { describe, it, expect, vi, beforeEach } from 'vitest'
import { defineBcsTypes } from './ika-client/bcs.js'

// Mock the gRPC singleton so `submitIkaTransaction` exercises only the
// decode/guard logic. `vi.hoisted` makes the fn available to the hoisted
// `vi.mock` factory.
const { submitTransaction } = vi.hoisted(() => ({ submitTransaction: vi.fn() }))
vi.mock('./grpc-client.js', () => ({
  getIkaGrpcClient: () => ({ submitTransaction }),
}))

const { submitIkaTransaction } = await import('./submit.js')

const T = defineBcsTypes()
const z32 = (): number[] => Array.from(new Uint8Array(32))
const z64 = (): number[] => Array.from(new Uint8Array(64))

function reply(responseData: Uint8Array | undefined): void {
  submitTransaction.mockResolvedValueOnce({ response_data: responseData })
}

describe('engine/submit — submitIkaTransaction guard', () => {
  beforeEach(() => {
    submitTransaction.mockReset()
  })

  it('rejects the explicit TransactionResponseData.Error variant', async () => {
    reply(T.TransactionResponseData.serialize({ Error: { message: 'network said no' } }).toBytes())
    await expect(submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })).rejects.toThrow(
      'Ika transaction rejected',
    )
  })

  it('accepts a Signature response and returns base64 of the raw bytes', async () => {
    const bytes = T.TransactionResponseData.serialize({ Signature: { signature: [1, 2, 3, 4] } }).toBytes()
    reply(bytes)
    const out = await submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })
    expect(out.responseKind).toBe('raw-bcs')
    expect(out.responseDataBase64).toBe(Buffer.from(bytes).toString('base64'))
  })

  it('accepts an Attestation response', async () => {
    const bytes = T.TransactionResponseData.serialize({
      Attestation: { attestation_data: [9, 9, 9], network_signature: z64(), network_pubkey: z32(), epoch: 3n },
    }).toBytes()
    reply(bytes)
    const out = await submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })
    expect(out.responseDataBase64).toBe(Buffer.from(bytes).toString('base64'))
  })

  it('rejects an empty response', async () => {
    reply(new Uint8Array(0))
    await expect(submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })).rejects.toThrow(
      'Invalid Ika response',
    )
  })

  it('rejects a non-Uint8Array response payload', async () => {
    submitTransaction.mockResolvedValueOnce({ response_data: undefined })
    await expect(submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })).rejects.toThrow(
      'Invalid Ika response',
    )
  })

  it('rejects bytes that do not decode to TransactionResponseData', async () => {
    reply(new Uint8Array([99]))
    await expect(submitIkaTransaction({ userSignature: new Uint8Array(0), signedRequestData: new Uint8Array(0) })).rejects.toThrow(
      'Ika returned an undecodable response',
    )
  })
})
