import { getIkaGrpcClient } from './grpc-client.js'

export interface IkaSubmitInput {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}

export interface RawBcsSubmitResult {
  responseKind: 'raw-bcs'
  responseDataBase64: string
}

// Per the local pinned proto comments, TransactionResponseData variants are
// ordered as Signature, Attestation, Presign, Error. BCS enum encoding stores
// the variant index first, so reject the explicit Error variant here even
// before the full typed decoder is wired.
const TRANSACTION_RESPONSE_ERROR_VARIANT = 3

/**
 * Relay one signed Ika request and reject responses that are definitely not
 * usable by the gateway. Full TransactionResponseData decoding depends on the
 * pinned upstream BCS schema; until that is wired, keep this guard centralized
 * so every primitive fails the same way instead of treating malformed output
 * as a successful operation.
 */
export async function submitIkaTransaction(input: IkaSubmitInput): Promise<RawBcsSubmitResult> {
  const client = getIkaGrpcClient()
  const resp = await client.submitTransaction({
    user_signature: input.userSignature,
    signed_request_data: input.signedRequestData,
  })
  const responseData = resp.response_data
  if (!(responseData instanceof Uint8Array) || responseData.length === 0) {
    throw new Error('Invalid Ika response')
  }
  if (responseData[0] === TRANSACTION_RESPONSE_ERROR_VARIANT) {
    throw new Error('Ika transaction rejected')
  }
  return {
    responseKind: 'raw-bcs',
    responseDataBase64: Buffer.from(responseData).toString('base64'),
  }
}
