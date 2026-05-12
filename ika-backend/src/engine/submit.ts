import { getIkaGrpcClient } from './grpc-client.js'
import { defineBcsTypes } from './ika-client/bcs.js'

export interface IkaSubmitInput {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}

export interface RawBcsSubmitResult {
  responseKind: 'raw-bcs'
  responseDataBase64: string
}

// `TransactionResponseData` has three variants in the vendored BCS schema
// (`ika-client/bcs.ts`, mirroring `crates/ika-dwallet-types/src/lib.rs`):
// `Signature`, `Attestation`, `Error`. The upstream `.proto` comment loosely
// lists a "Presign" variant — that does not exist on the wire; presigns come
// back wrapped in `Attestation` (`VersionedPresignDataAttestation`). The
// vendored codec is the source of truth here, so decode against it rather than
// hardcoding a variant index.
const T = defineBcsTypes()

function isErrorVariant(parsed: unknown): parsed is { Error: { message?: unknown } } {
  return typeof parsed === 'object' && parsed !== null && 'Error' in parsed
}

/**
 * Relay one signed Ika request and reject responses that are definitely not
 * usable by the gateway. The low-level routes hand the raw BCS bytes straight
 * back to the gateway, so this is the only place a network-side `Error` would
 * otherwise be treated as a successful operation — decode the envelope and fail
 * loudly on the `Error` variant (and on anything that does not decode at all).
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

  let parsed: unknown
  try {
    parsed = T.TransactionResponseData.parse(responseData)
  } catch {
    throw new Error('Ika returned an undecodable response')
  }
  if (isErrorVariant(parsed)) {
    throw new Error('Ika transaction rejected')
  }

  return {
    responseKind: 'raw-bcs',
    responseDataBase64: Buffer.from(responseData).toString('base64'),
  }
}
