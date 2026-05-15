/**
 * RulesPolicy program metadata: discriminators, seeds, error codes.
 * Mirrors `contracts/rules-policy/src/lib.rs` (v2 — challenge-based recovery).
 */

export const RULES_POLICY_INSTRUCTION_DISCRIMINATOR = {
  initPolicy: 0,
  recoverAsPrimary: 1,
  quorumSessionOpen: 2,
  quorumSessionContribute: 3,
  quorumSessionContributeWebauthn: 4,
  quorumSessionFinalize: 5,
  quorumSessionClose: 6,
  addMember: 7,
  removeMember: 8,
  addDestination: 9,
  removeDestination: 10,
  revoke: 11,
  setPrimary: 12,
  setQuorumThresholdImmediate: 13,
  setDailyLimitImmediate: 14,
  setCooldownImmediate: 15,
  proposeQuorumThresholdChange: 16,
  proposeDailyLimitChange: 17,
  proposeCooldownChange: 18,
  applyPendingChange: 19,
  // Login Social (`scheme = 4 = OidcJwt`) — see loginsocial.md §7.4.
  oidcJwtStage: 20,
  oidcSessionOpen: 21,
  recoverAsPrimaryOidcSession: 22,
  oidcSessionClose: 23,
  oidcJwtStagingClose: 24,
  // Keyspring Fase 2 — passkey session flow (D1 Opção A,
  // PLAN_KEYSPRING_INTEGRATION_2026_05.md).
  passkeySessionOpen: 25,
  recoverAsPrimaryPasskeySession: 26,
  passkeySessionClose: 27,
} as const

export const RULES_POLICY_ACCOUNT_DISCRIMINATOR = 1
export const QUORUM_SESSION_ACCOUNT_DISCRIMINATOR = 2
export const OIDC_SESSION_ACCOUNT_DISCRIMINATOR = 3
export const OIDC_JWT_STAGING_ACCOUNT_DISCRIMINATOR = 4
export const PASSKEY_SESSION_ACCOUNT_DISCRIMINATOR = 5

export const PENDING_CHANGE_KIND_NONE = 0
export const PENDING_CHANGE_KIND_QUORUM = 1
export const PENDING_CHANGE_KIND_DAILY_LIMIT = 2
export const PENDING_CHANGE_KIND_COOLDOWN = 3

export const RULES_POLICY_PDA_SEED = new TextEncoder().encode('rules_policy')
export const QUORUM_SESSION_PDA_SEED = new TextEncoder().encode('quorum_session')
export const OIDC_JWT_STAGING_PDA_SEED = new TextEncoder().encode('oidc_jwt_staging')
export const OIDC_SESSION_PDA_SEED = new TextEncoder().encode('oidc_session')
export const PASSKEY_SESSION_PDA_SEED = new TextEncoder().encode('passkey_session')
export const CPI_AUTHORITY_PDA_SEED = new TextEncoder().encode('__ika_cpi_authority')
export const EVENT_AUTHORITY_PDA_SEED = new TextEncoder().encode('__event_authority')

// ── Login Social — OIDC (`scheme = 4 = OidcJwt`) ─────────────────
//
// Mirrors the "Login Social constants" block in `contracts/rules-policy/src/lib.rs`
// and `contracts/jwk-registry`. See loginsocial.md §6–§8.

/** `andromeda_oidc_verifier::OIDC_VERIFIER_V1` — on-chain verifier format version. */
export const OIDC_VERIFIER_V1 = 1
/** `contracts/rules-policy::SESSION_TTL_SECONDS`. */
export const OIDC_SESSION_TTL_SECONDS = 600
/** `contracts/rules-policy::STAGING_TTL_SECONDS`. */
export const OIDC_STAGING_TTL_SECONDS = 15 * 60
/** Hard cap on a staged JWT (`OidcJwtStaging.jwt_bytes` / `oidc_verifier::MAX_JWT_LEN`). */
export const MAX_JWT_LEN = 4096
/** `andromeda_jwk_registry` program id (must own the `jwk_registry` account). */
export const JWK_REGISTRY_PROGRAM_ID = '8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM'
/** PDA seed prefix of the canonical `JwkRegistry` account. */
export const JWK_REGISTRY_PDA_SEED = new TextEncoder().encode('jwk_registry')
/** The canonical registry uses the all-zero `registry_seed`. */
export const CANONICAL_JWK_REGISTRY_SEED = new Uint8Array(32)

export const RULES_POLICY_ERROR = {
  INVALID_THRESHOLD: 6000,
  COOLDOWN_TOO_SHORT: 6001,
  TOO_MANY_MEMBERS: 6002,
  NOT_QUORUM_MEMBER: 6003,
  QUORUM_NOT_MET: 6004,
  DAILY_LIMIT_EXCEEDED: 6005,
  DESTINATION_NOT_ALLOWED: 6006,
  COOLDOWN_ACTIVE: 6007,
  NO_PENDING_CHANGE: 6008,
  DUPLICATE_MEMBER: 6009,
  INVALID_MEMBER_SLOT: 6010,
  INVALID_NONCE: 6011,
  AUTH_FAILED: 6012,
  UNSUPPORTED_SCHEME: 6013,
  SESSION_EXPIRED: 6014,
  SESSION_ALREADY_FINALIZED: 6015,
  SESSION_NOT_FINALIZED: 6016,
  SESSION_FINALIZABLE: 6017,
  INVALID_SESSION_TTL: 6018,
  ALREADY_CONTRIBUTED: 6019,
  INVALID_FLAG: 6020,
  COOLDOWN_TOO_LONG: 6021,
  // Login Social (`scheme = 4 = OidcJwt`)
  INVALID_JWK_REGISTRY: 6022,
  INVALID_JWT: 6023,
  JWK_NOT_ACTIVE: 6024,
  OIDC_VERIFY_FAILED: 6025,
  OIDC_VERIFIER_VERSION_MISMATCH: 6026,
  NOT_OIDC_PRIMARY: 6027,
  STAGING_NOT_EXPIRED: 6028,
  // Clear-signing renderer (shared across all clear-signing v2 flows).
  CLEAR_SIGNING_RENDER_FAILED: 6029,
  // Keyspring Fase 2 — passkey session flow.
  NOT_PASSKEY_PRIMARY: 6030,
  INVALID_WEBAUTHN_PAYLOAD: 6031,
  PASSKEY_CREDENTIAL_MISMATCH: 6032,
} as const

export const RULES_POLICY_EVENT_DISCRIMINATOR = {
  PolicyDeployed: 0,
  SignatureRequested: 1,
  SignatureApproved: 2,
  OidcSessionOpened: 3,
  PasskeySessionOpened: 4,
} as const

/** Keyspring Fase 2 — `contracts/rules-policy::SESSION_TTL_SECONDS` shared
 *  with OIDC sessions (10 min). */
export const PASSKEY_SESSION_TTL_SECONDS = 600

// ── Member-slot schemes (mirror auth/mod.rs) ─────────────────────

export const SCHEME_ED25519 = 0
export const SCHEME_SECP256K1 = 1
export const SCHEME_SECP256R1 = 2
export const SCHEME_WEBAUTHN = 3
/** `scheme = 4 = OidcJwt` — identifier = 32-byte `addr_seed` (Login Social).
 *  Only valid as a `RulesPolicy` *primary* slot. */
export const SCHEME_OIDC_JWT = 4

export const MEMBER_SLOT_LEN = 34
/** `addr_seed = sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`. */
export const OIDC_ADDR_SEED_LEN = 32

export const MAX_MEMBERS = 16
export const MAX_DESTINATIONS = 16
export const MAX_SESSION_TTL_SECONDS = 7 * 24 * 3600
export const MIN_COOLDOWN_SECONDS = 3600

// Keyspring Fase 0 spike (D13, 2026-05-14): bumped 64 → 192 after Samsung
// Pass returned `authData = 84 bytes` with PRF + ED flag active.
export const WEBAUTHN_AUTH_DATA_MAX = 192
export const WEBAUTHN_CLIENT_DATA_JSON_MAX = 192

/** Identifier byte length per scheme. */
export function idLenForScheme(scheme: number): number {
  switch (scheme) {
    case SCHEME_ED25519:
      return 32
    case SCHEME_SECP256K1:
      return 20
    case SCHEME_SECP256R1:
      return 33
    case SCHEME_WEBAUTHN:
      return 33
    case SCHEME_OIDC_JWT:
      return OIDC_ADDR_SEED_LEN
    default:
      throw new Error(`Unsupported scheme: ${scheme}`)
  }
}

/** Builds the canonical OIDC primary slot `[4, addr_seed(32), 0]`. */
export function buildOidcPrimarySlot(addrSeed: Uint8Array): Uint8Array {
  if (addrSeed.length !== OIDC_ADDR_SEED_LEN) {
    throw new Error(`addr_seed must be ${OIDC_ADDR_SEED_LEN} bytes, got ${addrSeed.length}`)
  }
  return buildMemberSlot(SCHEME_OIDC_JWT, addrSeed)
}

/** Builds the canonical passkey primary slot `[3, credential_pubkey(33)]`. */
export function buildPasskeyPrimarySlot(credentialPubkey: Uint8Array): Uint8Array {
  if (credentialPubkey.length !== 33) {
    throw new Error(`credential_pubkey must be 33 bytes (compressed Secp256r1), got ${credentialPubkey.length}`)
  }
  return buildMemberSlot(SCHEME_WEBAUTHN, credentialPubkey)
}

/**
 * Builds the canonical 34-byte member slot from `(scheme, identifier)`.
 * Throws if `identifier.length` does not match the scheme's expected size.
 */
export function buildMemberSlot(scheme: number, identifier: Uint8Array): Uint8Array {
  const expected = idLenForScheme(scheme)
  if (identifier.length !== expected) {
    throw new Error(
      `Identifier length ${identifier.length} does not match scheme ${scheme} (expected ${expected})`,
    )
  }
  const slot = new Uint8Array(MEMBER_SLOT_LEN)
  slot[0] = scheme
  slot.set(identifier, 1)
  return slot
}

/**
 * Extracts `{ scheme, identifier }` from a 34-byte member slot.
 * Verifies that the trailing bytes are zero-padded.
 */
export function parseMemberSlot(slot: Uint8Array): { scheme: number; identifier: Uint8Array } {
  if (slot.length !== MEMBER_SLOT_LEN) {
    throw new Error(`Member slot must be ${MEMBER_SLOT_LEN} bytes, got ${slot.length}`)
  }
  const scheme = slot[0]!
  const idLen = idLenForScheme(scheme)
  for (let i = 1 + idLen; i < MEMBER_SLOT_LEN; i += 1) {
    if (slot[i] !== 0) {
      throw new Error(`Member slot has non-zero padding at byte ${i}`)
    }
  }
  return { scheme, identifier: slot.slice(1, 1 + idLen) }
}
