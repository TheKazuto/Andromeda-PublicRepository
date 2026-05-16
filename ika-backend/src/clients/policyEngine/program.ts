/**
 * PolicyEngine v3 program metadata: discriminators, seeds, kinds, error codes.
 *
 * Mirrors `contracts/policy-engine/src/lib.rs` and `docs/POLICY_ENGINE_ABI_V3.md`.
 * Cross-language fixtures: `fixtures/policy_engine_v3/`.
 *
 * F2.4 status (2026-05-15): only the discs / seeds / constants needed for the
 * Allowlist vertical slice are listed below. Velocity/TimeLock/Oracle/etc.
 * land in F3..F9 as each kind ships.
 */

// ── Instruction discriminators ────────────────────────────────────────────

export const POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR = {
  initEngine: 0,
  requestSignature: 1,

  addRuleAllowlist: 10,
  addRuleVelocity: 11,
  addRuleTimeLock: 12,
  addRuleOracle: 13,
  addRulePasskey: 14,
  addRuleFheGated: 15,
  addRuleSessionKey: 16,
  addRuleRecovery: 17,

  removeRule: 50,
  pause: 60,
  resume: 61,
  revoke: 70,

  // Incremental item updates (PE-011 / ABI §7.X).
  updateRuleAllowlistAddDestination: 120,
  updateRuleAllowlistRemoveDestination: 121,
  updateRuleOracleAddFeed: 122,
  updateRuleOracleRemoveFeed: 123,
  updateRulePasskeyAddCredential: 124,
  updateRulePasskeyRemoveCredential: 125,
  // C2 audit fix (2026-05-16): disc 126 sets the entire authorities list at
  // once (not add/remove). The legacy add/remove granularity was aspirational
  // and never landed — granular API can be added later as a separate disc.
  updateRuleFheGatedAuthorities: 126,
  updateRuleSessionKeyAddDestination: 128,
  updateRuleSessionKeyRemoveDestination: 129,
  updateRuleRecoveryAddMember: 130,
  updateRuleRecoveryRemoveMember: 131,
  updateRuleRecoveryAddDestination: 132,
  updateRuleRecoveryRemoveDestination: 133,

  // F8b/F8c — SessionKey runtime instructions (ephemeral session lifecycle).
  sessionOpen: 100,
  requestSignatureViaSession: 101,
  sessionRevoke: 102,
  sessionClose: 103,
  closeExpiredSession: 104,
  sessionAddDestination: 105,
  sessionRemoveDestination: 106,

  // F9a — Recovery (primary path).
  recoverAsPrimary: 80,

  // F9b — Quorum recovery (M-of-N multi-tx staging).
  quorumSessionOpen: 82,
  quorumSessionContribute: 83,
  quorumSessionFinalize: 85,
  quorumSessionClose: 86,

  // F9d — Passkey recovery (Secp256r1 + WebAuthn assertion).
  passkeySessionOpen: 89,
  recoverAsPrimaryPasskeySession: 90,
  passkeySessionClose: 91,
} as const

// ── Account discriminators ────────────────────────────────────────────────

export const POLICY_ENGINE_ACCOUNT_DISCRIMINATOR = 1
export const RULE_ACCOUNT_DISCRIMINATOR = 2

// ── PDA seed prefixes ─────────────────────────────────────────────────────

const enc = new TextEncoder()

export const SEED_ENGINE = enc.encode('policy_engine')
export const SEED_RULE_ALLOWLIST = enc.encode('rule_allowlist')
export const SEED_RULE_VELOCITY = enc.encode('rule_velocity')
export const SEED_RULE_TIME_LOCK = enc.encode('rule_time_lock')
export const SEED_RULE_ORACLE = enc.encode('rule_oracle')
export const SEED_RULE_PASSKEY = enc.encode('rule_passkey')
export const SEED_RULE_FHE_GATED = enc.encode('rule_fhe_gated')
export const SEED_RULE_SESSION_KEY = enc.encode('rule_session_key')
export const SEED_RULE_RECOVERY = enc.encode('rule_recovery')
export const SEED_SESSION = enc.encode('session')
export const SEED_QUORUM_SESSION = enc.encode('quorum_session')
export const SEED_PASSKEY_SESSION = enc.encode('passkey_session')
export const SEED_CPI_AUTHORITY = enc.encode('__ika_cpi_authority')
export const SEED_EVENT_AUTHORITY = enc.encode('__event_authority')

// ── Rule kinds (ABI §3.3) ─────────────────────────────────────────────────

export const KIND_EMPTY = 0
export const KIND_ALLOWLIST = 1
export const KIND_VELOCITY = 2
export const KIND_TIME_LOCK = 3
export const KIND_ORACLE = 4
export const KIND_PASSKEY = 5
export const KIND_FHE_GATED = 6
export const KIND_SESSION_KEY = 7
export const KIND_RECOVERY = 8

export type RuleKind =
  | typeof KIND_EMPTY
  | typeof KIND_ALLOWLIST
  | typeof KIND_VELOCITY
  | typeof KIND_TIME_LOCK
  | typeof KIND_ORACLE
  | typeof KIND_PASSKEY
  | typeof KIND_FHE_GATED
  | typeof KIND_SESSION_KEY
  | typeof KIND_RECOVERY

export function seedForKind(kind: RuleKind): Uint8Array {
  switch (kind) {
    case KIND_ALLOWLIST:
      return SEED_RULE_ALLOWLIST
    case KIND_VELOCITY:
      return SEED_RULE_VELOCITY
    case KIND_TIME_LOCK:
      return SEED_RULE_TIME_LOCK
    case KIND_ORACLE:
      return SEED_RULE_ORACLE
    case KIND_PASSKEY:
      return SEED_RULE_PASSKEY
    case KIND_FHE_GATED:
      return SEED_RULE_FHE_GATED
    case KIND_SESSION_KEY:
      return SEED_RULE_SESSION_KEY
    case KIND_RECOVERY:
      return SEED_RULE_RECOVERY
    default:
      throw new Error(`policyEngine: kind ${kind} has no PDA seed`)
  }
}

// ── AppliesTo bitmask (ADR PE-006) ────────────────────────────────────────

export const APPLIES_NORMAL = 1
export const APPLIES_RECOVERY = 2
export const APPLIES_SESSION = 4
export const APPLIES_ALL = APPLIES_NORMAL | APPLIES_RECOVERY | APPLIES_SESSION

// ── Caps (mirror lib.rs constants) ────────────────────────────────────────

export const MAX_RULES = 16
export const MEMBER_SLOT_LEN = 34
export const MAX_ALLOWLIST_DESTINATIONS = 32
export const SESSION_MAX_DESTINATIONS = 8
export const MAX_RECOVERY_MEMBERS = 16
export const MAX_RECOVERY_DESTINATIONS = 16
export const WEBAUTHN_AUTH_DATA_MAX = 192
export const WEBAUTHN_CLIENT_DATA_JSON_MAX = 192

// ── Error codes (ABI §4) ──────────────────────────────────────────────────

export const POLICY_ENGINE_ERROR = {
  GENERIC_ERROR: 6000,
  ENGINE_PAUSED: 6001,
  ACCOUNT_ALREADY_INITIALIZED: 6002,
  ACCOUNT_NOT_INITIALIZED: 6003,
  TOO_MANY_RULES: 6004,
  RULE_ALREADY_ACTIVE: 6005,
  RULE_SLOT_IN_USE: 6006,
  RULE_NOT_FOUND: 6007,
  INVALID_RULE_VERSION: 6008,
  INVALID_RULE_KIND: 6009,
  INVALID_RULE_HEADER: 6010,
  RULE_NOT_APPLICABLE: 6011,
  RULE_DISABLED: 6012,
  INVALID_NONCE: 6020,
  INVALID_OWNER_SLOT: 6021,
  INVALID_INIT_AUTHORITY_SLOT: 6022,
  UNSUPPORTED_SCHEME: 6023,
  AUTH_FAILED: 6024,
  CLEAR_SIGNING_RENDER_FAILED: 6025,
  ALLOWLIST_DESTINATION_NOT_ALLOWED: 6030,
  VELOCITY_CAP_EXCEEDED: 6031,
  TIME_LOCKED: 6032,
  ORACLE_STALE: 6033,
  ORACLE_OUT_OF_BAND: 6034,
  ORACLE_OWNER_MISMATCH: 6035,
  PASSKEY_STEP_UP_REQUIRED: 6036,
  PASSKEY_STEP_UP_INVALID: 6037,
  FHE_DECISION_MISSING: 6038,
  FHE_DECISION_INVALID: 6039,
  SESSION_EXPIRED: 6040,
  SESSION_CAP_EXCEEDED: 6041,
  SESSION_DESTINATION_NOT_ALLOWED: 6042,
  SESSION_NOT_FOUND: 6043,
  RECOVERY_QUORUM_NOT_REACHED: 6050,
  RECOVERY_MEMBER_NOT_IN_QUORUM: 6051,
  RECOVERY_DAILY_LIMIT_EXCEEDED: 6052,
  RECOVERY_COOLDOWN_ACTIVE: 6053,
  RECOVERY_DESTINATION_NOT_ALLOWED: 6054,
  PENDING_CHANGE_MISMATCH: 6055,
  PENDING_CHANGE_NOT_READY: 6056,
  OIDC_SESSION_EXPIRED: 6060,
  OIDC_JWT_INVALID: 6061,
  OIDC_JWK_NOT_FOUND: 6062,
  OIDC_AUDIENCE_MISMATCH: 6063,
  OIDC_ISSUER_MISMATCH: 6064,
  PASSKEY_ASSERTION_INVALID: 6065,
  PASSKEY_SESSION_EXPIRED: 6066,
  IKA_CPI_ACCOUNT_MISMATCH: 6070,
  IKA_CPI_FAILED: 6071,
  DELEGATION_NOT_CONFIRMED: 6080,
} as const
