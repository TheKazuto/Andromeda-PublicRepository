import { z } from 'zod'
import { randomBytes } from 'node:crypto'
import bs58 from 'bs58'
import { submitIkaTransaction, type RawBcsSubmitResult } from './submit.js'
import { resolveEpoch } from './ika-client/request.js'
import { defineBcsTypes, Curve, type CurveName } from './ika-client/bcs.js'

/**
 * DKG — Distributed Key Generation (low-level relay path).
 *
 * Two-phase, custody-free:
 *   1. `prepareDkg` builds the BCS-serialized `SignedRequestData` (the DKG
 *      request) with the current Ika epoch and a fresh 32-byte session
 *      preimage baked in.
 *   2. The caller signs those bytes with their Ed25519 signer key, BCS-encodes
 *      a `UserSignature` enum, and POSTs both to `/v1/dwallet/dkg/submit`,
 *      which relays them to the Ika gRPC service (`submitDkg` → `submitIkaTransaction`).
 *
 * The high-level, tenant-scoped path is `/v1/dwallet/create` (it does steps 1+2
 * server-side using the keystore key) — see `ika-client/request.ts`. This
 * low-level path is for callers that hold the signer key themselves.
 *
 * Pre-alpha: the network runs a single mock signer, so the MPC fields below are
 * zero-filled placeholders and the caller's `UserSignature` is zeros too. At
 * Alpha 1 those become real 2PC-MPC outputs and this layer pairs with a Rust
 * MPC module (see `ika-client/request.ts` `MpcAdapter`).
 */

const T = defineBcsTypes()

const CURVE_NAMES = ['Secp256k1', 'Secp256r1', 'Curve25519', 'Ristretto'] as const

export const dkgRequestSchema = z.object({
  curve: z.enum(CURVE_NAMES),
  /**
   * Base58-encoded 32-byte Ed25519 public key of the caller's signer key. This
   * becomes the dWallet owner / `intended_chain_sender`.
   */
  userPublicKeyBase58: z.string().min(32).max(64),
})

export type DkgRequest = z.infer<typeof dkgRequestSchema>

export interface DkgPrepareResult {
  /** BCS-serialized `SignedRequestData` (base64). The caller signs these exact bytes. */
  signedRequestDataBase64: string
  /** The 32-byte session preimage baked into the payload (base64) — keep it; reused for follow-ups. */
  sessionPreimageBase64: string
  /** The Ika epoch baked into the payload. */
  epoch: string
  /** `intended_chain_sender` = the caller's signer pubkey (base58, echoed back). */
  intendedChainSenderBase58: string
  curve: CurveName
  curveId: number
  notes: string
}

// `@mysten/bcs` enum inputs only type-check against fresh inline literals, so
// hold the variant objects in a typed map. Runtime is exact.
const CURVE_VARIANT: Record<CurveName, { Secp256k1: true } | { Secp256r1: true } | { Curve25519: true } | { Ristretto: true }> = {
  Secp256k1: { Secp256k1: true },
  Secp256r1: { Secp256r1: true },
  Curve25519: { Curve25519: true },
  Ristretto: { Ristretto: true },
}

const zeros32 = (): number[] => Array.from(new Uint8Array(32))

function decodeEd25519Pubkey(b58: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = bs58.decode(b58.trim())
  } catch {
    throw new Error('Invalid userPublicKeyBase58')
  }
  if (bytes.length !== 32) throw new Error('Invalid userPublicKeyBase58 (expected a 32-byte Ed25519 key)')
  return bytes
}

/**
 * Build the BCS `SignedRequestData` for a DKG request. The caller signs the
 * returned bytes and submits via `/v1/dwallet/dkg/submit`.
 */
export async function prepareDkg(input: DkgRequest): Promise<DkgPrepareResult> {
  const senderPubkey = decodeEd25519Pubkey(input.userPublicKeyBase58)
  const sessionPreimage = new Uint8Array(randomBytes(32))
  const epoch = await resolveEpoch(senderPubkey)
  const curveId = Curve[input.curve]

  const signedRequestData = T.SignedRequestData.serialize({
    session_identifier_preimage: Array.from(sessionPreimage),
    epoch,
    chain_id: { Solana: true },
    intended_chain_sender: Array.from(senderPubkey),
    request: {
      DKG: {
        dwallet_network_encryption_public_key: zeros32(),
        curve: CURVE_VARIANT[input.curve],
        centralized_public_key_share_and_proof: zeros32(),
        user_secret_key_share: {
          Encrypted: {
            encrypted_centralized_secret_share_and_proof: zeros32(),
            encryption_key: zeros32(),
            signer_public_key: Array.from(senderPubkey),
          },
        },
        user_public_output: zeros32(),
        sign_during_dkg_request: null,
      },
    },
  }).toBytes()

  return {
    signedRequestDataBase64: Buffer.from(signedRequestData).toString('base64'),
    sessionPreimageBase64: Buffer.from(sessionPreimage).toString('base64'),
    epoch: epoch.toString(),
    intendedChainSenderBase58: bs58.encode(senderPubkey),
    curve: input.curve,
    curveId,
    notes:
      'Sign signedRequestData (raw bytes) with the Ed25519 signer key, BCS-serialize a UserSignature ' +
      'enum { Ed25519: { signature, public_key } } (pre-alpha: signature = 64 zero bytes, public_key = the ' +
      'signer pubkey), then POST { userSignatureBase64, signedRequestDataBase64 } to /v1/dwallet/dkg/submit. ' +
      'The response is the raw NetworkSignedAttestation (BCS); decode it to read the dWallet public key and ' +
      'derive the dWallet PDA from (curveId, publicKey).',
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
