import { submitIkaTransaction } from './submit.js'

/**
 * FutureSign — two-step conditional signing.
 *
 * Step 1 (FutureSign): user pre-commits to signing a specific message; network
 *   stores partial user signature; PartialUserSignature attestation returned.
 *
 * Step 2 (SignWithPartialUserSig): given the attestation + on-chain conditions,
 *   network completes the signature.
 *
 * Useful for "approve now, sign later when policy condition is met" flows
 * where the message is known up-front but the on-chain trigger is future.
 */

export async function submitFutureSign(input: {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}): Promise<{ responseKind: 'raw-bcs'; responseDataBase64: string }> {
  return submitIkaTransaction(input)
}

export async function submitSignWithPartialUserSig(input: {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}): Promise<{ responseKind: 'raw-bcs'; responseDataBase64: string }> {
  return submitIkaTransaction(input)
}
