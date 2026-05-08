import { z } from 'zod'
import { submitIkaTransaction, type RawBcsSubmitResult } from './submit.js'
import type { DWalletCurve } from '../types.js'

/**
 * DKG — Distributed Key Generation.
 *
 * Two-phase: client builds the request → backend forwards to Ika gRPC →
 * NetworkSignedAttestation comes back. The NOA later commits the dWallet
 * on-chain via `commit_dwallet` (instruction discriminator 31).
 *
 * BCS encoding/decoding of `SignedRequestData` and the response is handled
 * here. The `proto/` directory must contain the upstream Ika .proto files;
 * BCS schemas are inferred from `crates/ika-dwallet-types/`.
 *
 * TODO: hook BCS schemas once `proto/` is populated. Until then, the prepare
 * step returns the unsigned envelope structure for the client to assemble.
 */

export const dkgRequestSchema = z.object({
  curve: z.enum(['Secp256k1', 'Secp256r1', 'Curve25519', 'Ristretto']),
  userPublicKeyBase58: z.string().min(32),
  intendedChainSender: z.string(),
  encryptedShare: z.boolean().default(true),
})

export type DkgRequest = z.infer<typeof dkgRequestSchema>

export interface DkgPrepareResult {
  envelopeHint: {
    chainId: 'Solana'
    curve: DWalletCurve
    epochField: 'fetch-from-validator-network'
    sessionIdentifierBytes: 32
  }
  notes: string
}

/**
 * Returns metadata that the client uses to assemble the BCS-serialized
 * SignedRequestData payload. In pre-alpha, the heavy crypto (encryption key
 * generation, share encryption) lives client-side; the backend only relays
 * the request after the client signs it.
 */
export function prepareDkg(_input: DkgRequest): DkgPrepareResult {
  return {
    envelopeHint: {
      chainId: 'Solana',
      curve: _input.curve,
      epochField: 'fetch-from-validator-network',
      sessionIdentifierBytes: 32,
    },
    notes:
      'Client must sign signed_request_data with Ed25519 user key and submit via /v1/dwallet/dkg/submit.',
  }
}

export interface DkgSubmitInput {
  userSignature: Uint8Array
  signedRequestData: Uint8Array
}

export type DkgSubmitResult = RawBcsSubmitResult

export async function submitDkg(input: DkgSubmitInput): Promise<DkgSubmitResult> {
  return submitIkaTransaction(input)
}
