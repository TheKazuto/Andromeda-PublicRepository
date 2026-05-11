// BCS type definitions for the Ika dWallet gRPC wire format.
//
// Vendored from `dwallet-labs/ika-pre-alpha`
// (`chains/solana/clients/typescript/src/bcs-types.ts`, rev
// `3bd7945e012950e54fb4d0057b72a7d466556fc1` — the same rev `contracts/`
// pins for `ika-dwallet-quasar`). Mirrors `crates/ika-dwallet-types/src/lib.rs`.
// Keep this in sync with that rev; re-vendor (don't paraphrase) on upgrade —
// the network rejects any byte mismatch.
//
// Original: Copyright (c) dWallet Labs, Ltd. — SPDX-License-Identifier: BSD-3-Clause-Clear
//
// Pre-alpha note: the network runs a single mock signer, so every MPC field
// below (`centralized_public_key_share_and_proof`,
// `encrypted_centralized_secret_share_and_proof`, `encryption_key`,
// `message_centralized_signature`) is sent as a zero-filled placeholder.
// When Ika ships Alpha, those become real cryptographic outputs and this
// layer pairs with a Rust MPC module — see `src/engine/ika-client/mpc.ts`.

import { bcs } from '@mysten/bcs'

export function defineBcsTypes() {
  const ChainId = bcs.enum('ChainId', { Solana: null, Sui: null })
  const DWalletCurve = bcs.enum('DWalletCurve', {
    Secp256k1: null,
    Secp256r1: null,
    Curve25519: null,
    Ristretto: null,
  })
  // Internal granular enums kept for legacy / debugging — not used on the wire
  // by current request types. The user-facing wire format uses
  // `DWalletSignatureScheme` (algorithm + hash combined).
  const DWalletSignatureAlgorithm = bcs.enum('DWalletSignatureAlgorithm', {
    ECDSASecp256k1: null,
    ECDSASecp256r1: null,
    Taproot: null,
    EdDSA: null,
    SchnorrkelSubstrate: null,
  })
  const DWalletHashScheme = bcs.enum('DWalletHashScheme', {
    Keccak256: null,
    SHA256: null,
    DoubleSHA256: null,
    SHA512: null,
    Merlin: null,
  })
  // Combined (algorithm, hash) pair — the on-wire signature scheme.
  // Order matches Rust enum discriminants.
  const DWalletSignatureScheme = bcs.enum('DWalletSignatureScheme', {
    EcdsaKeccak256: null,
    EcdsaSha256: null,
    EcdsaDoubleSha256: null,
    TaprootSha256: null,
    EcdsaBlake2b256: null,
    EddsaSha512: null,
    SchnorrkelMerlin: null,
  })

  const ApprovalProof = bcs.enum('ApprovalProof', {
    Solana: bcs.struct('APS', {
      transaction_signature: bcs.vector(bcs.u8()),
      slot: bcs.u64(),
    }),
    Sui: bcs.struct('APSui', { effects_certificate: bcs.vector(bcs.u8()) }),
  })

  const UserSignature = bcs.enum('UserSignature', {
    Ed25519: bcs.struct('USE', {
      signature: bcs.vector(bcs.u8()),
      public_key: bcs.vector(bcs.u8()),
    }),
    Secp256k1: bcs.struct('USS', {
      signature: bcs.vector(bcs.u8()),
      public_key: bcs.vector(bcs.u8()),
    }),
    Secp256r1: bcs.struct('USR', {
      signature: bcs.vector(bcs.u8()),
      public_key: bcs.vector(bcs.u8()),
    }),
  })

  const NetworkSignedAttestation = bcs.struct('NetworkSignedAttestation', {
    attestation_data: bcs.vector(bcs.u8()),
    network_signature: bcs.vector(bcs.u8()),
    network_pubkey: bcs.vector(bcs.u8()),
    epoch: bcs.u64(),
  })

  const SignDuringDKGRequest = bcs.struct('SignDuringDKGRequest', {
    presign_session_identifier: bcs.vector(bcs.u8()),
    presign: bcs.vector(bcs.u8()),
    signature_scheme: DWalletSignatureScheme,
    message: bcs.vector(bcs.u8()),
    message_metadata: bcs.vector(bcs.u8()),
    message_centralized_signature: bcs.vector(bcs.u8()),
  })

  const UserSecretKeyShare = bcs.enum('UserSecretKeyShare', {
    Encrypted: bcs.struct('USKSEnc', {
      encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
      encryption_key: bcs.vector(bcs.u8()),
      signer_public_key: bcs.vector(bcs.u8()),
    }),
    Public: bcs.struct('USKSPub', {
      public_user_secret_key_share: bcs.vector(bcs.u8()),
    }),
  })

  const DWalletRequest = bcs.enum('DWalletRequest', {
    DKG: bcs.struct('DKG', {
      dwallet_network_encryption_public_key: bcs.vector(bcs.u8()),
      curve: DWalletCurve,
      centralized_public_key_share_and_proof: bcs.vector(bcs.u8()),
      user_secret_key_share: UserSecretKeyShare,
      user_public_output: bcs.vector(bcs.u8()),
      sign_during_dkg_request: bcs.option(SignDuringDKGRequest),
    }),
    Sign: bcs.struct('Sign', {
      message: bcs.vector(bcs.u8()),
      message_metadata: bcs.vector(bcs.u8()),
      presign_session_identifier: bcs.vector(bcs.u8()),
      message_centralized_signature: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      approval_proof: ApprovalProof,
    }),
    ImportedKeySign: bcs.struct('IKS', {
      message: bcs.vector(bcs.u8()),
      message_metadata: bcs.vector(bcs.u8()),
      presign_session_identifier: bcs.vector(bcs.u8()),
      message_centralized_signature: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      approval_proof: ApprovalProof,
    }),
    Presign: bcs.struct('Presign', {
      dwallet_network_encryption_public_key: bcs.vector(bcs.u8()),
      curve: DWalletCurve,
      signature_algorithm: DWalletSignatureAlgorithm,
    }),
    PresignForDWallet: bcs.struct('PFD', {
      dwallet_network_encryption_public_key: bcs.vector(bcs.u8()),
      dwallet_public_key: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      curve: DWalletCurve,
      signature_algorithm: DWalletSignatureAlgorithm,
    }),
    ImportedKeyVerification: bcs.struct('IKV', {
      dwallet_network_encryption_public_key: bcs.vector(bcs.u8()),
      curve: DWalletCurve,
      centralized_party_message: bcs.vector(bcs.u8()),
      user_secret_key_share: UserSecretKeyShare,
      user_public_output: bcs.vector(bcs.u8()),
    }),
    ReEncryptShare: bcs.struct('ReEncryptShare', {
      dwallet_network_encryption_public_key: bcs.vector(bcs.u8()),
      dwallet_public_key: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
      encryption_key: bcs.vector(bcs.u8()),
    }),
    MakeSharePublic: bcs.struct('MakeSharePublic', {
      dwallet_public_key: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      public_user_secret_key_share: bcs.vector(bcs.u8()),
    }),
    FutureSign: bcs.struct('FutureSign', {
      dwallet_public_key: bcs.vector(bcs.u8()),
      dwallet_attestation: NetworkSignedAttestation,
      presign_session_identifier: bcs.vector(bcs.u8()),
      message: bcs.vector(bcs.u8()),
      message_metadata: bcs.vector(bcs.u8()),
      message_centralized_signature: bcs.vector(bcs.u8()),
      signature_scheme: DWalletSignatureScheme,
    }),
    SignWithPartialUserSig: bcs.struct('SWPUS', {
      partial_user_signature_attestation: NetworkSignedAttestation,
      dwallet_attestation: NetworkSignedAttestation,
      approval_proof: ApprovalProof,
    }),
    ImportedKeySignWithPartialUserSig: bcs.struct('IKSWPUS', {
      partial_user_signature_attestation: NetworkSignedAttestation,
      dwallet_attestation: NetworkSignedAttestation,
      approval_proof: ApprovalProof,
    }),
  })

  const SignedRequestData = bcs.struct('SignedRequestData', {
    session_identifier_preimage: bcs.fixedArray(32, bcs.u8()),
    epoch: bcs.u64(),
    chain_id: ChainId,
    intended_chain_sender: bcs.vector(bcs.u8()),
    request: DWalletRequest,
  })

  // Three response variants: Signature (self-verifying), Attestation
  // (NOA-signed wrapper covering DKG / FutureSign / ReEncrypt /
  // MakeSharePublic / ImportedKeyVerification AND presigns), Error.
  // BCS tuple variants serialize the inner type directly (no field name),
  // so `Attestation` references `NetworkSignedAttestation` as a payload type.
  const TransactionResponseData = bcs.enum('TransactionResponseData', {
    Signature: bcs.struct('SigResp', { signature: bcs.vector(bcs.u8()) }),
    Attestation: NetworkSignedAttestation,
    Error: bcs.struct('ErrResp', { message: bcs.string() }),
  })

  // attestation_data payloads (decode NetworkSignedAttestation.attestation_data with these)
  const VersionedDWalletDataAttestation = bcs.enum('VersionedDWalletDataAttestation', {
    V1: bcs.struct('DWalletDataAttestationV1', {
      session_identifier: bcs.fixedArray(32, bcs.u8()),
      intended_chain_sender: bcs.vector(bcs.u8()),
      curve: DWalletCurve,
      public_key: bcs.vector(bcs.u8()),
      public_output: bcs.vector(bcs.u8()),
      is_imported_key: bcs.bool(),
      sign_during_dkg_signature: bcs.option(bcs.vector(bcs.u8())),
    }),
  })

  const VersionedPresignDataAttestation = bcs.enum('VersionedPresignDataAttestation', {
    V1: bcs.struct('PresignDataAttestationV1', {
      session_identifier: bcs.fixedArray(32, bcs.u8()),
      epoch: bcs.u64(),
      presign_session_identifier: bcs.vector(bcs.u8()),
      presign_data: bcs.vector(bcs.u8()),
      curve: DWalletCurve,
      signature_algorithm: DWalletSignatureAlgorithm,
      dwallet_public_key: bcs.option(bcs.vector(bcs.u8())),
      user_pubkey: bcs.vector(bcs.u8()),
    }),
  })

  // Per-scheme message metadata structs
  const Blake2bMessageMetadata = bcs.struct('Blake2bMessageMetadata', {
    personal: bcs.vector(bcs.u8()),
    salt: bcs.vector(bcs.u8()),
  })
  const SchnorrkelMessageMetadata = bcs.struct('SchnorrkelMessageMetadata', {
    context: bcs.vector(bcs.u8()),
  })

  return {
    ChainId,
    DWalletCurve,
    DWalletSignatureAlgorithm,
    DWalletHashScheme,
    DWalletSignatureScheme,
    ApprovalProof,
    UserSignature,
    NetworkSignedAttestation,
    SignDuringDKGRequest,
    UserSecretKeyShare,
    DWalletRequest,
    SignedRequestData,
    TransactionResponseData,
    VersionedDWalletDataAttestation,
    VersionedPresignDataAttestation,
    Blake2bMessageMetadata,
    SchnorrkelMessageMetadata,
  }
}

// Curve / scheme / algorithm numeric ids (mirror the skill + the Rust enums).
export const Curve = {
  Secp256k1: 0,
  Secp256r1: 1,
  Curve25519: 2,
  Ristretto: 3,
} as const

export const SignatureScheme = {
  EcdsaKeccak256: 0,
  EcdsaSha256: 1,
  EcdsaDoubleSha256: 2,
  TaprootSha256: 3,
  EcdsaBlake2b256: 4,
  EddsaSha512: 5,
  SchnorrkelMerlin: 6,
} as const

export const SignatureAlgorithm = {
  ECDSASecp256k1: 0,
  ECDSASecp256r1: 1,
  Taproot: 2,
  EdDSA: 3,
  Schnorrkel: 4,
} as const

export type CurveName = keyof typeof Curve
