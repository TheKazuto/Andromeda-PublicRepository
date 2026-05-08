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
} as const

export const RULES_POLICY_ACCOUNT_DISCRIMINATOR = 1
export const QUORUM_SESSION_ACCOUNT_DISCRIMINATOR = 2

export const PENDING_CHANGE_KIND_NONE = 0
export const PENDING_CHANGE_KIND_QUORUM = 1
export const PENDING_CHANGE_KIND_DAILY_LIMIT = 2
export const PENDING_CHANGE_KIND_COOLDOWN = 3

export const RULES_POLICY_PDA_SEED = new TextEncoder().encode('rules_policy')
export const QUORUM_SESSION_PDA_SEED = new TextEncoder().encode('quorum_session')
export const CPI_AUTHORITY_PDA_SEED = new TextEncoder().encode('__ika_cpi_authority')
export const EVENT_AUTHORITY_PDA_SEED = new TextEncoder().encode('__event_authority')

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
} as const

export const RULES_POLICY_EVENT_DISCRIMINATOR = {
  PolicyDeployed: 0,
  SignatureRequested: 1,
  SignatureApproved: 2,
} as const

// ── Member-slot schemes (mirror auth/mod.rs) ─────────────────────

export const SCHEME_ED25519 = 0
export const SCHEME_SECP256K1 = 1
export const SCHEME_SECP256R1 = 2
export const SCHEME_WEBAUTHN = 3

export const MEMBER_SLOT_LEN = 34

export const MAX_MEMBERS = 16
export const MAX_DESTINATIONS = 16
export const MAX_SESSION_TTL_SECONDS = 7 * 24 * 3600
export const MIN_COOLDOWN_SECONDS = 3600

export const WEBAUTHN_AUTH_DATA_MAX = 64
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
    default:
      throw new Error(`Unsupported scheme: ${scheme}`)
  }
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
