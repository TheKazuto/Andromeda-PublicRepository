import { submitIkaTransaction } from './submit.js'

/**
 * ReEncryptShare — re-encrypt the user's centralized secret key share under
 * a new encryption key. Used when rotating the user's encryption key
 * without re-doing DKG.
 *
 * MakeSharePublic — one-way transition from encrypted to public mode for the
 * user share. Cannot be undone; downstream operations no longer require the
 * encrypted-share path.
 */

export async function submitReEncryptShare(input: {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}): Promise<{ responseKind: 'raw-bcs'; responseDataBase64: string }> {
  return submitIkaTransaction(input)
}

export async function submitMakeSharePublic(input: {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}): Promise<{ responseKind: 'raw-bcs'; responseDataBase64: string }> {
  return submitIkaTransaction(input)
}
