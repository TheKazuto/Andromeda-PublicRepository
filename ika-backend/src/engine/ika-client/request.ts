// High-level Ika dWallet client: builds, signs, and submits the gRPC requests
// for DKG / Presign / Sign, and decodes the responses. This is the "Andromeda
// does the client side" path (used by POST /v1/dwallet/{create,sign,presign}),
// distinct from the low-level relay in `../submit.ts` (where the caller already
// did the crypto).
//
// PRE-ALPHA: the network runs a single mock signer, so every MPC field is a
// zero-filled placeholder and the user-signature is zeros too — see the
// `MpcAdapter` interface and `preAlphaMockMpc`. When Ika ships Alpha, swap in
// a real adapter (the Rust MPC library via a sidecar/WASM) — nothing else here
// changes shape.

import { randomBytes } from 'node:crypto'
import { getProgramDerivedAddress, type Address } from '@solana/kit'
import { getIkaGrpcClient } from '../grpc-client.js'
import { logger } from '../../logger.js'
import { defineBcsTypes, type CurveName } from './bcs.js'

const T = defineBcsTypes()

// ── MPC adapter ──────────────────────────────────────────────────────────
// Everything cryptographically heavy in the 2PC-MPC protocol goes through
// this interface so the pre-alpha stub (zeros) and a future real adapter
// (Rust crypto) are interchangeable.

export interface DkgCentralizedOutput {
  centralizedPublicKeyShareAndProof: Uint8Array
  encryptedCentralizedSecretShareAndProof: Uint8Array
  encryptionKey: Uint8Array
  userPublicOutput: Uint8Array
}

export interface MpcAdapter {
  /** Centralized-party DKG output. */
  dkgCentralized(curve: CurveName): DkgCentralizedOutput
  /** Centralized-party signature contribution over `message`. */
  signCentralized(curve: CurveName, message: Uint8Array, presignId: Uint8Array): Uint8Array
  /** The `UserSignature` over `bcs(SignedRequestData)`. Pre-alpha: zeros. */
  userSignature(signerPubkey: Uint8Array, signedRequestData: Uint8Array): {
    Ed25519: { signature: number[]; public_key: number[] }
  }
}

/** Pre-alpha mock adapter: every MPC field is zeros, the user-sig is zeros. */
export const preAlphaMockMpc: MpcAdapter = {
  dkgCentralized() {
    return {
      centralizedPublicKeyShareAndProof: new Uint8Array(32),
      encryptedCentralizedSecretShareAndProof: new Uint8Array(32),
      encryptionKey: new Uint8Array(32),
      userPublicOutput: new Uint8Array(32),
    }
  },
  signCentralized() {
    return new Uint8Array(64)
  },
  userSignature(signerPubkey) {
    return { Ed25519: { signature: Array.from(new Uint8Array(64)), public_key: Array.from(signerPubkey) } }
  },
}

let mpc: MpcAdapter = preAlphaMockMpc
export function setMpcAdapter(adapter: MpcAdapter): void {
  mpc = adapter
}

// ── Curve / chain helpers ────────────────────────────────────────────────

// Typed `any` because @mysten/bcs's enum input shape only type-checks against
// fresh inline literals, not values held in a map. Runtime is fine.
const CURVE_VARIANT: Record<CurveName, any> = {
  Secp256k1: { Secp256k1: true },
  Secp256r1: { Secp256r1: true },
  Curve25519: { Curve25519: true },
  Ristretto: { Ristretto: true },
}

// (curve → presign signature algorithm) — the algorithm used to allocate a
// presign for that curve. Hash is applied at sign time.
const CURVE_PRESIGN_ALGO: Record<CurveName, any> = {
  Secp256k1: { ECDSASecp256k1: true },
  Secp256r1: { ECDSASecp256r1: true },
  Curve25519: { EdDSA: true },
  Ristretto: { SchnorrkelSubstrate: true },
}

// ── Epoch ────────────────────────────────────────────────────────────────
// `SignedRequestData.epoch` must match the current Ika epoch. We refresh it
// from GetPresigns when possible; pre-alpha is lenient, so fall back to 1.

let epochCache: { value: bigint; at: number } | null = null
const EPOCH_TTL_MS = 30_000

export async function resolveEpoch(senderPubkey: Uint8Array): Promise<bigint> {
  const now = Date.now()
  if (epochCache && now - epochCache.at < EPOCH_TTL_MS) return epochCache.value
  let value = 1n
  try {
    const presigns = await getIkaGrpcClient().getPresigns(senderPubkey)
    const first = presigns[0]
    if (first && typeof first.epoch === 'bigint') value = first.epoch
  } catch (err) {
    logger.debug({ err }, 'epoch refresh via GetPresigns failed; using default 1')
  }
  epochCache = { value, at: now }
  return value
}

// ── Submit + decode ──────────────────────────────────────────────────────

export type DecodedResponse =
  | { kind: 'signature'; signature: Uint8Array }
  | { kind: 'attestation'; attestationData: Uint8Array; networkSignature: Uint8Array; networkPubkey: Uint8Array; epoch: bigint }
  | { kind: 'error'; message: string }

async function submitAndDecode(signedRequestData: Uint8Array, signerPubkey: Uint8Array): Promise<DecodedResponse> {
  const userSig = T.UserSignature.serialize(mpc.userSignature(signerPubkey, signedRequestData)).toBytes()
  const resp = await getIkaGrpcClient().submitTransaction({
    user_signature: userSig,
    signed_request_data: signedRequestData,
  })
  if (!(resp.response_data instanceof Uint8Array) || resp.response_data.length === 0) {
    throw new Error('Ika returned an empty response')
  }
  const parsed = T.TransactionResponseData.parse(resp.response_data) as any
  if (parsed.Signature) return { kind: 'signature', signature: new Uint8Array(parsed.Signature.signature) }
  if (parsed.Attestation) {
    const a = parsed.Attestation
    return {
      kind: 'attestation',
      attestationData: new Uint8Array(a.attestation_data),
      networkSignature: new Uint8Array(a.network_signature),
      networkPubkey: new Uint8Array(a.network_pubkey),
      epoch: BigInt(a.epoch),
    }
  }
  if (parsed.Error) return { kind: 'error', message: String(parsed.Error.message) }
  return { kind: 'error', message: 'unrecognized TransactionResponseData variant' }
}

// ── dWallet PDA derivation (post-DKG) ────────────────────────────────────
// seeds = [b"dwallet", chunks_of(curve_u16_le || public_key)]  (Ika program)

const DWALLET_SEED = new TextEncoder().encode('dwallet')

export async function deriveDwalletAddress(
  curveId: number,
  publicKey: Uint8Array,
  ikaProgramId: Address,
): Promise<{ address: Address; bump: number }> {
  const concat = new Uint8Array(2 + publicKey.length)
  concat[0] = curveId & 0xff
  concat[1] = (curveId >> 8) & 0xff
  concat.set(publicKey, 2)
  const chunks: Uint8Array[] = []
  for (let i = 0; i < concat.length; i += 32) chunks.push(concat.slice(i, Math.min(i + 32, concat.length)))
  const [addr, bump] = await getProgramDerivedAddress({
    programAddress: ikaProgramId,
    seeds: [DWALLET_SEED, ...chunks],
  })
  return { address: addr, bump }
}

// ── High-level operations ────────────────────────────────────────────────

export interface DkgResult {
  /** Random 32-byte session preimage used for this DKG (reuse for follow-ups). */
  sessionPreimage: Uint8Array
  /** dWallet public key from the network attestation. */
  publicKey: Uint8Array
  publicOutput: Uint8Array
  /** Raw NetworkSignedAttestation parts — store these; needed for every later Sign. */
  attestationData: Uint8Array
  networkSignature: Uint8Array
  networkPubkey: Uint8Array
}

/**
 * Run DKG via gRPC. `senderPubkey` is the chain sender / future dWallet owner
 * (Andromeda generates this per user — see the keystore layer). Does NOT touch
 * Solana; the NOA submits `commit_dwallet` afterwards (paid from the gas
 * sponsor's GasDeposit). The caller derives the dWallet PDA from
 * `(curve, publicKey)` via `deriveDwalletAddress` and reads the account.
 */
export async function requestDkg(params: {
  curve: CurveName
  senderPubkey: Uint8Array
}): Promise<DkgResult> {
  const { curve, senderPubkey } = params
  const sessionPreimage = new Uint8Array(randomBytes(32))
  const epoch = await resolveEpoch(senderPubkey)
  const m = mpc.dkgCentralized(curve)

  const signedData = T.SignedRequestData.serialize({
    session_identifier_preimage: Array.from(sessionPreimage),
    epoch,
    chain_id: { Solana: true },
    intended_chain_sender: Array.from(senderPubkey),
    request: {
      DKG: {
        dwallet_network_encryption_public_key: Array.from(new Uint8Array(32)),
        curve: CURVE_VARIANT[curve],
        centralized_public_key_share_and_proof: Array.from(m.centralizedPublicKeyShareAndProof),
        user_secret_key_share: {
          Encrypted: {
            encrypted_centralized_secret_share_and_proof: Array.from(m.encryptedCentralizedSecretShareAndProof),
            encryption_key: Array.from(m.encryptionKey),
            signer_public_key: Array.from(senderPubkey),
          },
        },
        user_public_output: Array.from(m.userPublicOutput),
        sign_during_dkg_request: null,
      },
    },
  }).toBytes()

  const resp = await submitAndDecode(signedData, senderPubkey)
  if (resp.kind === 'error') throw new Error(`DKG rejected: ${resp.message}`)
  if (resp.kind !== 'attestation') throw new Error('DKG: expected an attestation response')

  const payload = T.VersionedDWalletDataAttestation.parse(resp.attestationData) as any
  if (!payload.V1) throw new Error('DKG: unexpected attestation payload variant')

  return {
    sessionPreimage,
    publicKey: new Uint8Array(payload.V1.public_key),
    publicOutput: new Uint8Array(payload.V1.public_output),
    attestationData: resp.attestationData,
    networkSignature: resp.networkSignature,
    networkPubkey: resp.networkPubkey,
  }
}

/**
 * Allocate one single-use global presign for `curve` — reusable across
 * non-imported dWallets of that curve. (Imported ECDSA keys would need the
 * per-dWallet flavor `PresignForDWallet`; MCP-created wallets are not imported.)
 * Returns the presign session identifier. For throughput, allocate in batches.
 */
export async function requestPresign(params: {
  curve: CurveName
  senderPubkey: Uint8Array
}): Promise<Uint8Array> {
  const { curve, senderPubkey } = params
  const epoch = await resolveEpoch(senderPubkey)

  const signedData = T.SignedRequestData.serialize({
    session_identifier_preimage: Array.from(new Uint8Array(randomBytes(32))),
    epoch,
    chain_id: { Solana: true },
    intended_chain_sender: Array.from(senderPubkey),
    request: {
      Presign: {
        dwallet_network_encryption_public_key: Array.from(new Uint8Array(32)),
        curve: CURVE_VARIANT[curve],
        signature_algorithm: CURVE_PRESIGN_ALGO[curve],
      },
    },
  }).toBytes()

  const resp = await submitAndDecode(signedData, senderPubkey)
  if (resp.kind === 'error') throw new Error(`Presign rejected: ${resp.message}`)
  if (resp.kind !== 'attestation') throw new Error('Presign: expected an attestation response')
  const payload = T.VersionedPresignDataAttestation.parse(resp.attestationData) as {
    V1?: { presign_session_identifier: number[] }
  }
  if (!payload.V1) throw new Error('Presign: unexpected attestation payload variant')
  return new Uint8Array(payload.V1.presign_session_identifier)
}

/**
 * Produce a signature for `message` (RAW, un-hashed — the network applies the
 * hash from the scheme). Requires: a presign id (from `requestPresign`), the
 * dWallet's stored attestation, and an `approvalProof` referencing the Solana
 * tx that created the on-chain MessageApproval (`status=Pending`,
 * `message_digest=keccak256(message)`, `message_metadata_digest=keccak256(meta)
 * or 32×0`). Returns the raw signature; the caller assembles the destination
 * chain's transaction.
 */
export async function requestSign(params: {
  curve: CurveName
  senderPubkey: Uint8Array
  message: Uint8Array
  messageMetadata?: Uint8Array
  presignSessionId: Uint8Array
  dwalletAttestationData: Uint8Array
  dwalletNetworkSignature: Uint8Array
  dwalletNetworkPubkey: Uint8Array
  approvalTxSignature: Uint8Array
  approvalSlot: bigint
}): Promise<Uint8Array> {
  const { curve, senderPubkey, message } = params
  const epoch = await resolveEpoch(senderPubkey)

  const signedData = T.SignedRequestData.serialize({
    session_identifier_preimage: Array.from(new Uint8Array(randomBytes(32))),
    epoch,
    chain_id: { Solana: true },
    intended_chain_sender: Array.from(senderPubkey),
    request: {
      Sign: {
        message: Array.from(message),
        message_metadata: Array.from(params.messageMetadata ?? new Uint8Array(0)),
        presign_session_identifier: Array.from(params.presignSessionId),
        message_centralized_signature: Array.from(mpc.signCentralized(curve, message, params.presignSessionId)),
        dwallet_attestation: {
          attestation_data: Array.from(params.dwalletAttestationData),
          network_signature: Array.from(params.dwalletNetworkSignature),
          network_pubkey: Array.from(params.dwalletNetworkPubkey),
          epoch,
        },
        approval_proof: {
          Solana: { transaction_signature: Array.from(params.approvalTxSignature), slot: params.approvalSlot },
        },
      },
    },
  }).toBytes()

  const resp = await submitAndDecode(signedData, senderPubkey)
  if (resp.kind === 'error') throw new Error(`Sign rejected: ${resp.message}`)
  if (resp.kind !== 'signature') throw new Error('Sign: expected a signature response')
  return resp.signature
}

// Re-export the numeric ids + the curve-name type for callers wiring the HTTP layer.
export { Curve, SignatureScheme, SignatureAlgorithm } from './bcs.js'
export type { CurveName } from './bcs.js'
