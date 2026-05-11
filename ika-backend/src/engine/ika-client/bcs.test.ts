import { describe, it, expect } from 'vitest'
import { defineBcsTypes, Curve, SignatureScheme, SignatureAlgorithm } from './bcs.js'

const T = defineBcsTypes()
const z32 = (): number[] => Array.from(new Uint8Array(32))
const z64 = (): number[] => Array.from(new Uint8Array(64))
// @mysten/bcs serializes u64 from a bigint and parses it back as a string (or
// bigint depending on version) — normalize via BigInt() for assertions.
const u64 = (v: unknown): bigint => BigInt(v as string | number | bigint)

describe('ika-client/bcs — wire format round-trips (catches schema drift vs ika-pre-alpha)', () => {
  it('round-trips a DKG SignedRequestData', () => {
    const value = {
      session_identifier_preimage: Array.from({ length: 32 }, (_, i) => i),
      epoch: 1n,
      chain_id: { Solana: true },
      intended_chain_sender: z32(),
      request: {
        DKG: {
          dwallet_network_encryption_public_key: z32(),
          curve: { Curve25519: true },
          centralized_public_key_share_and_proof: z32(),
          user_secret_key_share: {
            Encrypted: {
              encrypted_centralized_secret_share_and_proof: z32(),
              encryption_key: z32(),
              signer_public_key: z32(),
            },
          },
          user_public_output: z32(),
          sign_during_dkg_request: null,
        },
      },
    }
    const parsed = T.SignedRequestData.parse(T.SignedRequestData.serialize(value).toBytes()) as any
    expect(parsed.session_identifier_preimage).toEqual(value.session_identifier_preimage)
    expect(u64(parsed.epoch)).toBe(1n)
    expect(parsed.chain_id).toHaveProperty('Solana')
    expect(parsed.request).toHaveProperty('DKG')
    expect(parsed.request.DKG.curve).toHaveProperty('Curve25519')
    expect(parsed.request.DKG.centralized_public_key_share_and_proof).toEqual(z32())
    expect(parsed.request.DKG.user_secret_key_share).toHaveProperty('Encrypted')
    expect(parsed.request.DKG.sign_during_dkg_request).toBeNull()
  })

  it('round-trips a Sign SignedRequestData', () => {
    const att = { attestation_data: z32(), network_signature: z64(), network_pubkey: z32(), epoch: 7n }
    const value = {
      session_identifier_preimage: z32(),
      epoch: 7n,
      chain_id: { Solana: true },
      intended_chain_sender: z32(),
      request: {
        Sign: {
          message: [1, 2, 3],
          message_metadata: [],
          presign_session_identifier: [9, 9],
          message_centralized_signature: z64(),
          dwallet_attestation: att,
          approval_proof: { Solana: { transaction_signature: z64(), slot: 123n } },
        },
      },
    }
    const parsed = T.SignedRequestData.parse(T.SignedRequestData.serialize(value).toBytes()) as any
    expect(parsed.request).toHaveProperty('Sign')
    expect(parsed.request.Sign.message).toEqual([1, 2, 3])
    expect(parsed.request.Sign.message_metadata).toEqual([])
    expect(parsed.request.Sign.presign_session_identifier).toEqual([9, 9])
    expect(parsed.request.Sign.approval_proof).toHaveProperty('Solana')
    expect(u64(parsed.request.Sign.approval_proof.Solana.slot)).toBe(123n)
  })

  it('round-trips a Presign SignedRequestData', () => {
    const value = {
      session_identifier_preimage: z32(),
      epoch: 1n,
      chain_id: { Solana: true },
      intended_chain_sender: z32(),
      request: { Presign: { dwallet_network_encryption_public_key: z32(), curve: { Curve25519: true }, signature_algorithm: { EdDSA: true } } },
    }
    const parsed = T.SignedRequestData.parse(T.SignedRequestData.serialize(value).toBytes()) as any
    expect(parsed.request).toHaveProperty('Presign')
    expect(parsed.request.Presign.curve).toHaveProperty('Curve25519')
    expect(parsed.request.Presign.signature_algorithm).toHaveProperty('EdDSA')
  })

  it('round-trips UserSignature (Ed25519)', () => {
    const parsed = T.UserSignature.parse(T.UserSignature.serialize({ Ed25519: { signature: z64(), public_key: z32() } }).toBytes()) as any
    expect(parsed).toHaveProperty('Ed25519')
    expect(parsed.Ed25519.signature).toEqual(z64())
    expect(parsed.Ed25519.public_key).toEqual(z32())
  })

  it('round-trips TransactionResponseData (Attestation, Error, Signature)', () => {
    const att = { attestation_data: [1, 2, 3], network_signature: z64(), network_pubkey: z32(), epoch: 5n }
    const a = T.TransactionResponseData.parse(T.TransactionResponseData.serialize({ Attestation: att }).toBytes()) as any
    expect(a).toHaveProperty('Attestation')
    expect(a.Attestation.attestation_data).toEqual([1, 2, 3])
    expect(u64(a.Attestation.epoch)).toBe(5n)

    const e = T.TransactionResponseData.parse(T.TransactionResponseData.serialize({ Error: { message: 'boom' } }).toBytes()) as any
    expect(e.Error.message).toBe('boom')

    const s = T.TransactionResponseData.parse(T.TransactionResponseData.serialize({ Signature: { signature: [10, 20, 30] } }).toBytes()) as any
    expect(s.Signature.signature).toEqual([10, 20, 30])
  })

  it('round-trips the versioned attestation payloads', () => {
    const dkgAtt = {
      V1: {
        session_identifier: z32(),
        intended_chain_sender: z32(),
        curve: { Curve25519: true },
        public_key: Array.from({ length: 32 }, (_, i) => i + 1),
        public_output: [],
        is_imported_key: false,
        sign_during_dkg_signature: null,
      },
    }
    const d = T.VersionedDWalletDataAttestation.parse(T.VersionedDWalletDataAttestation.serialize(dkgAtt).toBytes()) as any
    expect(d.V1.public_key).toEqual(Array.from({ length: 32 }, (_, i) => i + 1))
    expect(d.V1.is_imported_key).toBe(false)
    expect(d.V1.sign_during_dkg_signature).toBeNull()

    const psAtt = {
      V1: {
        session_identifier: z32(),
        epoch: 1n,
        presign_session_identifier: [7, 7, 7],
        presign_data: [],
        curve: { Curve25519: true },
        signature_algorithm: { EdDSA: true },
        dwallet_public_key: null,
        user_pubkey: z32(),
      },
    }
    const p = T.VersionedPresignDataAttestation.parse(T.VersionedPresignDataAttestation.serialize(psAtt).toBytes()) as any
    expect(p.V1.presign_session_identifier).toEqual([7, 7, 7])
    expect(p.V1.dwallet_public_key).toBeNull()
  })

  it('numeric id constants match the enum discriminant order', () => {
    expect(Curve).toEqual({ Secp256k1: 0, Secp256r1: 1, Curve25519: 2, Ristretto: 3 })
    expect(SignatureScheme.EddsaSha512).toBe(5)
    expect(SignatureScheme.EcdsaKeccak256).toBe(0)
    expect(SignatureAlgorithm.EdDSA).toBe(3)
    expect(SignatureAlgorithm.ECDSASecp256k1).toBe(0)
  })
})
