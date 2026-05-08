import { z } from 'zod'
import { getIkaGrpcClient } from './grpc-client.js'
import { submitIkaTransaction } from './submit.js'

/**
 * Presign — allocate signing material ahead of time.
 *   - global Presign: reusable across non-imported dWallets (same curve).
 *   - per-dWallet PresignForDWallet: required for imported ECDSA keys.
 *
 * Both are single-use. Track consumption client-side; the network rejects
 * double-spend but the error is opaque.
 */

export const presignRequestSchema = z.object({
  curve: z.enum(['Secp256k1', 'Secp256r1', 'Curve25519', 'Ristretto']),
  algorithm: z.enum(['ECDSASecp256k1', 'ECDSASecp256r1', 'Taproot', 'EdDSA', 'Schnorrkel']),
  forDwalletPublicKeyBase58: z.string().optional(),
})

export type PresignRequest = z.infer<typeof presignRequestSchema>

export async function submitPresign(input: {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}): Promise<{ responseKind: 'raw-bcs'; responseDataBase64: string }> {
  return submitIkaTransaction(input)
}

export async function listPresigns(userPubkey: Uint8Array): Promise<
  Array<{
    presignId: Uint8Array
    dwalletId: Uint8Array
    curve: number
    signatureScheme: number
    epoch: bigint
  }>
> {
  const items = await getIkaGrpcClient().getPresigns(userPubkey)
  return items.map((p) => ({
    presignId: p.presign_id,
    dwalletId: p.dwallet_id,
    curve: p.curve,
    signatureScheme: p.signature_scheme,
    epoch: p.epoch,
  }))
}
