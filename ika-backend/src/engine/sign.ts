import { z } from 'zod'
import { submitIkaTransaction, type RawBcsSubmitResult } from './submit.js'

/**
 * Sign — produces a signature over `message` using an existing dWallet.
 *
 * Pre-conditions on Solana side:
 *   1. A MessageApproval PDA exists with status=Pending, message_digest =
 *      keccak256(message), message_metadata_digest matching metadata.
 *   2. The transaction that created the MessageApproval is referenced via
 *      ApprovalProof::Solana { transaction_signature, slot }.
 *   3. A presign exists and is referenced by `presign_session_identifier`.
 *
 * The network applies the hash function from `signature_scheme`, so callers
 * MUST pass the un-hashed message bytes.
 */

export const signRequestSchema = z.object({
  messageBase64: z.string(),
  messageMetadataBase64: z.string().default(''),
  presignSessionIdentifierHex: z.string(),
  approvalTxSignatureBase58: z.string(),
  approvalSlot: z.coerce.bigint(),
})

export type SignRequest = z.infer<typeof signRequestSchema>

export interface SignSubmitInput {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}

export type SignSubmitResult = RawBcsSubmitResult

export async function submitSign(input: SignSubmitInput): Promise<SignSubmitResult> {
  return submitIkaTransaction(input)
}
