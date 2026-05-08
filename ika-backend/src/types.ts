export interface ApiSuccess<T> {
  success: true
  data: T
}

export interface ApiFailure {
  success: false
  error: string
  traceId?: string
}

export type ApiResponse<T> = ApiSuccess<T> | ApiFailure

export function ok<T>(data: T): ApiSuccess<T> {
  return { success: true, data }
}

export function fail(error: string, traceId?: string): ApiFailure {
  const payload: ApiFailure = { success: false, error }
  if (traceId) payload.traceId = traceId
  return payload
}

export type DWalletCurve = 'Secp256k1' | 'Secp256r1' | 'Curve25519' | 'Ristretto'

export const CURVE_TO_ID: Record<DWalletCurve, number> = {
  Secp256k1: 0,
  Secp256r1: 1,
  Curve25519: 2,
  Ristretto: 3,
}

export type DWalletSignatureScheme =
  | 'EcdsaKeccak256'
  | 'EcdsaSha256'
  | 'EcdsaDoubleSha256'
  | 'TaprootSha256'
  | 'EcdsaBlake2b256'
  | 'EddsaSha512'
  | 'SchnorrkelMerlin'

export const SCHEME_TO_ID: Record<DWalletSignatureScheme, number> = {
  EcdsaKeccak256: 0,
  EcdsaSha256: 1,
  EcdsaDoubleSha256: 2,
  TaprootSha256: 3,
  EcdsaBlake2b256: 4,
  EddsaSha512: 5,
  SchnorrkelMerlin: 6,
}

export type DWalletSignatureAlgorithm =
  | 'ECDSASecp256k1'
  | 'ECDSASecp256r1'
  | 'Taproot'
  | 'EdDSA'
  | 'Schnorrkel'

export const ALGORITHM_TO_ID: Record<DWalletSignatureAlgorithm, number> = {
  ECDSASecp256k1: 0,
  ECDSASecp256r1: 1,
  Taproot: 2,
  EdDSA: 3,
  Schnorrkel: 4,
}

export interface DWalletAccountState {
  address: string
  authority: string
  curve: DWalletCurve
  state: 'DKGInProgress' | 'Active' | 'Frozen'
  publicKey: Uint8Array
  createdEpoch: bigint
  isImported: boolean
  bump: number
}

export interface MessageApprovalState {
  address: string
  dwallet: string
  messageDigest: Uint8Array
  messageMetadataDigest: Uint8Array
  approver: string
  userPubkey: Uint8Array
  signatureScheme: DWalletSignatureScheme
  epoch: bigint
  status: 'Pending' | 'Signed'
  signature: Uint8Array | null
  bump: number
}
