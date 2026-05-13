/**
 * Manual codecs for `contracts/rules-policy/src/lib.rs` (v2 + Login Social).
 *
 * Four account types, each prefixed by a single-byte Quasar discriminator:
 *  - `RulesPolicy`     (disc = 1)
 *  - `QuorumSession`   (disc = 2)
 *  - `OidcSession`     (disc = 3) — Login Social
 *  - `OidcJwtStaging`  (disc = 4) — Login Social
 *
 * Members are stored as canonical 34-byte slots:
 * `[scheme, ...identifier, 0..0]`. Scheme tags and identifier lengths are
 * defined in `program.ts`.
 */

import {
  MAX_DESTINATIONS,
  MAX_MEMBERS,
  MEMBER_SLOT_LEN,
  OIDC_ADDR_SEED_LEN,
  OIDC_JWT_STAGING_ACCOUNT_DISCRIMINATOR,
  OIDC_SESSION_ACCOUNT_DISCRIMINATOR,
  PENDING_CHANGE_KIND_NONE,
  QUORUM_SESSION_ACCOUNT_DISCRIMINATOR,
  RULES_POLICY_ACCOUNT_DISCRIMINATOR,
  parseMemberSlot,
} from './program.js'

const LE = true
// Quasar `#[account(discriminator = N)]` emits a single-byte account
// discriminator (`RulesPolicy` = 1, `QuorumSession` = 2 — see `program.ts`),
// not an 8-byte Anchor-style one. The first account field (`dwallet`) starts
// at byte offset 1.
export const ACCOUNT_DISCRIMINATOR_LEN = 1
export const ADDRESS_LEN = 32
export const MEMBERS_FLAT_SIZE = MAX_MEMBERS * MEMBER_SLOT_LEN // 544
export const DESTINATIONS_FLAT_SIZE = MAX_DESTINATIONS * ADDRESS_LEN // 512

// Audit C2 (Opção 4): RulesPolicy stores `init_authority_slot` for traceability.
// Login Social (Fase 3b): + `next_oidc_session_nonce` + `next_staging_nonce`
// (after `next_session_nonce`) — 16 more bytes; **all offsets after
// `next_session_nonce` shifted accordingly.**
export const RULES_POLICY_ACCOUNT_SIZE =
  32 + // dwallet
  MEMBER_SLOT_LEN + // primary_slot
  MEMBER_SLOT_LEN + // init_authority_slot (Audit C2)
  8 + // next_admin_nonce
  8 + // next_primary_recover_nonce
  8 + // next_session_nonce
  8 + // next_oidc_session_nonce (Login Social)
  8 + // next_staging_nonce (Login Social)
  6 + // quorum_threshold + member_count + daily_limit_some + allowed_destinations_some + allowed_destinations_count + pending_change_some
  MEMBERS_FLAT_SIZE +
  DESTINATIONS_FLAT_SIZE +
  8 + // daily_limit
  8 + // daily_used
  8 + // last_reset_ts
  8 + // policy_change_cooldown_seconds
  8 + // pending_activates_at
  1 + // pending_quorum_threshold
  1 + // pending_daily_limit_some
  8 + // pending_daily_limit
  8 // pending_cooldown_seconds

export const QUORUM_SESSION_ACCOUNT_SIZE =
  32 + // dwallet
  32 + // policy
  32 + // payer_for_close
  8 + // session_nonce
  32 + // message_digest
  32 + // metadata_digest
  32 + // user_pubkey
  32 + // destination
  MEMBERS_FLAT_SIZE +
  8 + // amount
  8 + // expires_at
  8 + // created_at
  8 + // finalized_at
  2 + // signature_scheme
  1 + // member_count_snapshot
  1 + // threshold_snapshot
  1 + // message_approval_bump
  1 + // contributions_count
  2 // contributions_bitmap

// ── Login Social account sizes (mirror `contracts/rules-policy/src/lib.rs`) ──

export const OIDC_JWT_BYTES_LEN = 4096
export const OIDC_JWT_STAGING_ACCOUNT_SIZE =
  32 + // dwallet
  32 + // policy
  32 + // payer_for_close
  8 + // staging_nonce
  8 + // created_at
  2 + // jwt_len (u16)
  OIDC_JWT_BYTES_LEN // jwt_bytes [u8; 4096]

export const OIDC_SESSION_ACCOUNT_SIZE =
  32 + // dwallet
  32 + // policy
  32 + // payer_for_close
  32 + // jwk_registry
  OIDC_ADDR_SEED_LEN + // addr_seed
  32 + // eph_pk
  32 + // issuer_hash
  32 + // audience_hash
  32 + // kid_hash
  8 + // session_nonce
  8 + // next_use_nonce
  8 + // not_after_unix_ts
  8 + // exp_from_jwt
  8 + // expires_at
  8 + // created_at
  8 + // closed_at
  4 // oidc_verifier_version (u32)

// ── ByteWriter / ByteReader ─────────────────────────────────────

export class ByteWriter {
  private chunks: Uint8Array[] = []
  private len = 0

  writeU8(v: number): void {
    const b = new Uint8Array(1)
    b[0] = v & 0xff
    this.writeBytes(b)
  }

  writeU16LE(v: number): void {
    const b = new Uint8Array(2)
    new DataView(b.buffer).setUint16(0, v, LE)
    this.writeBytes(b)
  }

  writeU32LE(v: number): void {
    const b = new Uint8Array(4)
    new DataView(b.buffer).setUint32(0, v, LE)
    this.writeBytes(b)
  }

  writeU64LE(v: bigint): void {
    const b = new Uint8Array(8)
    new DataView(b.buffer).setBigUint64(0, v, LE)
    this.writeBytes(b)
  }

  writeI64LE(v: bigint): void {
    const b = new Uint8Array(8)
    new DataView(b.buffer).setBigInt64(0, v, LE)
    this.writeBytes(b)
  }

  writeBytes(buf: Uint8Array): void {
    this.chunks.push(buf)
    this.len += buf.length
  }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this.len)
    let off = 0
    for (const c of this.chunks) {
      out.set(c, off)
      off += c.length
    }
    return out
  }
}

export class ByteReader {
  private off = 0
  private readonly view: DataView

  constructor(private readonly src: Uint8Array) {
    this.view = new DataView(src.buffer, src.byteOffset, src.byteLength)
  }

  readU8(): number {
    const v = this.view.getUint8(this.off)
    this.off += 1
    return v
  }

  readU16LE(): number {
    const v = this.view.getUint16(this.off, LE)
    this.off += 2
    return v
  }

  readU32LE(): number {
    const v = this.view.getUint32(this.off, LE)
    this.off += 4
    return v
  }

  readU64LE(): bigint {
    const v = this.view.getBigUint64(this.off, LE)
    this.off += 8
    return v
  }

  readI64LE(): bigint {
    const v = this.view.getBigInt64(this.off, LE)
    this.off += 8
    return v
  }

  readBytes(n: number): Uint8Array {
    const v = this.src.slice(this.off, this.off + n)
    this.off += n
    return v
  }

  skip(n: number): void {
    this.off += n
  }
}

// ── Member-slot helpers ─────────────────────────────────────────

export interface MemberSlotData {
  scheme: number
  identifier: Uint8Array
  raw: Uint8Array
}

function readFlatSlots(reader: ByteReader, count: number, max: number): MemberSlotData[] {
  if (count > max) throw new Error(`member count ${count} exceeds max=${max}`)
  const slots: MemberSlotData[] = []
  for (let i = 0; i < count; i += 1) {
    const raw = reader.readBytes(MEMBER_SLOT_LEN)
    const { scheme, identifier } = parseMemberSlot(raw)
    slots.push({ scheme, identifier, raw })
  }
  reader.skip((max - count) * MEMBER_SLOT_LEN)
  return slots
}

function readFlatAddresses(reader: ByteReader, count: number, max: number): Uint8Array[] {
  if (count > max) throw new Error(`address count ${count} exceeds max=${max}`)
  const out: Uint8Array[] = []
  for (let i = 0; i < count; i += 1) {
    out.push(reader.readBytes(ADDRESS_LEN))
  }
  reader.skip((max - count) * ADDRESS_LEN)
  return out
}

// ── RulesPolicy ─────────────────────────────────────────────────

export interface PendingChangeData {
  kind: number
  activatesAt: bigint
  newQuorumThreshold: number
  newDailyLimitSome: number
  newDailyLimit: bigint
  newCooldownSeconds: bigint
}

export interface RulesPolicyAccountData {
  dwallet: Uint8Array
  primarySlot: MemberSlotData
  /** Audit C2 (Opção 4): the slot that signed the init challenge. */
  initAuthoritySlot: MemberSlotData
  nextAdminNonce: bigint
  nextPrimaryRecoverNonce: bigint
  nextSessionNonce: bigint
  /** Login Social: single-use nonce space for `oidc_session_open`. */
  nextOidcSessionNonce: bigint
  /** Login Social: single-use nonce space for `oidc_jwt_stage`. */
  nextStagingNonce: bigint
  quorumThreshold: number
  memberCount: number
  dailyLimitSome: number
  allowedDestinationsSome: number
  allowedDestinationsCount: number
  pendingChangeKind: number
  members: MemberSlotData[]
  allowedDestinations: Uint8Array[]
  dailyLimit: bigint
  dailyUsed: bigint
  lastResetTs: bigint
  policyChangeCooldownSeconds: bigint
  pendingChange: PendingChangeData
}

export function decodeRulesPolicyAccount(raw: Uint8Array): RulesPolicyAccountData {
  if (raw.length < ACCOUNT_DISCRIMINATOR_LEN + RULES_POLICY_ACCOUNT_SIZE) {
    throw new Error(
      `RulesPolicy account too small: got ${raw.length}, need at least ${ACCOUNT_DISCRIMINATOR_LEN + RULES_POLICY_ACCOUNT_SIZE}`,
    )
  }
  if (raw[0] !== RULES_POLICY_ACCOUNT_DISCRIMINATOR) {
    throw new Error(`RulesPolicy discriminator mismatch: ${raw[0]}`)
  }

  const r = new ByteReader(raw.subarray(ACCOUNT_DISCRIMINATOR_LEN))
  const dwallet = r.readBytes(32)
  const primarySlotRaw = r.readBytes(MEMBER_SLOT_LEN)
  const { scheme: primaryScheme, identifier: primaryIdentifier } = parseMemberSlot(primarySlotRaw)
  const primarySlot: MemberSlotData = {
    scheme: primaryScheme,
    identifier: primaryIdentifier,
    raw: primarySlotRaw,
  }
  // Audit C2 (Opção 4): init_authority_slot follows primary_slot in storage.
  const initAuthoritySlotRaw = r.readBytes(MEMBER_SLOT_LEN)
  const { scheme: initScheme, identifier: initIdentifier } = parseMemberSlot(initAuthoritySlotRaw)
  const initAuthoritySlot: MemberSlotData = {
    scheme: initScheme,
    identifier: initIdentifier,
    raw: initAuthoritySlotRaw,
  }
  const nextAdminNonce = r.readU64LE()
  const nextPrimaryRecoverNonce = r.readU64LE()
  const nextSessionNonce = r.readU64LE()
  const nextOidcSessionNonce = r.readU64LE()
  const nextStagingNonce = r.readU64LE()
  const quorumThreshold = r.readU8()
  const memberCount = r.readU8()
  const dailyLimitSome = r.readU8()
  const allowedDestinationsSome = r.readU8()
  const allowedDestinationsCount = r.readU8()
  const pendingChangeKind = r.readU8()
  const members = readFlatSlots(r, memberCount, MAX_MEMBERS)
  const allowedDestinations = readFlatAddresses(r, allowedDestinationsCount, MAX_DESTINATIONS)
  const dailyLimit = r.readU64LE()
  const dailyUsed = r.readU64LE()
  const lastResetTs = r.readI64LE()
  const policyChangeCooldownSeconds = r.readU64LE()
  const pendingActivatesAt = r.readI64LE()
  const pendingQuorumThreshold = r.readU8()
  const pendingDailyLimitSome = r.readU8()
  const pendingDailyLimit = r.readU64LE()
  const pendingCooldownSeconds = r.readU64LE()

  return {
    dwallet,
    primarySlot,
    initAuthoritySlot,
    nextAdminNonce,
    nextPrimaryRecoverNonce,
    nextSessionNonce,
    nextOidcSessionNonce,
    nextStagingNonce,
    quorumThreshold,
    memberCount,
    dailyLimitSome,
    allowedDestinationsSome,
    allowedDestinationsCount,
    pendingChangeKind,
    members,
    allowedDestinations,
    dailyLimit,
    dailyUsed,
    lastResetTs,
    policyChangeCooldownSeconds,
    pendingChange: {
      kind: pendingChangeKind,
      activatesAt: pendingActivatesAt,
      newQuorumThreshold: pendingQuorumThreshold,
      newDailyLimitSome: pendingDailyLimitSome,
      newDailyLimit: pendingDailyLimit,
      newCooldownSeconds: pendingCooldownSeconds,
    },
  }
}

export function pendingChangeIsNone(data: RulesPolicyAccountData): boolean {
  return data.pendingChangeKind === PENDING_CHANGE_KIND_NONE
}

// ── QuorumSession ───────────────────────────────────────────────

export interface QuorumSessionAccountData {
  dwallet: Uint8Array
  policy: Uint8Array
  payerForClose: Uint8Array
  sessionNonce: bigint
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  destination: Uint8Array
  membersSnapshot: MemberSlotData[]
  amount: bigint
  expiresAt: bigint
  createdAt: bigint
  finalizedAt: bigint
  signatureScheme: number
  memberCountSnapshot: number
  thresholdSnapshot: number
  messageApprovalBump: number
  contributionsCount: number
  contributionsBitmap: number
}

export function decodeQuorumSessionAccount(raw: Uint8Array): QuorumSessionAccountData {
  if (raw.length < ACCOUNT_DISCRIMINATOR_LEN + QUORUM_SESSION_ACCOUNT_SIZE) {
    throw new Error(
      `QuorumSession account too small: got ${raw.length}, need at least ${ACCOUNT_DISCRIMINATOR_LEN + QUORUM_SESSION_ACCOUNT_SIZE}`,
    )
  }
  if (raw[0] !== QUORUM_SESSION_ACCOUNT_DISCRIMINATOR) {
    throw new Error(`QuorumSession discriminator mismatch: ${raw[0]}`)
  }

  const r = new ByteReader(raw.subarray(ACCOUNT_DISCRIMINATOR_LEN))
  const dwallet = r.readBytes(32)
  const policy = r.readBytes(32)
  const payerForClose = r.readBytes(32)
  const sessionNonce = r.readU64LE()
  const messageDigest = r.readBytes(32)
  const metadataDigest = r.readBytes(32)
  const userPubkey = r.readBytes(32)
  const destination = r.readBytes(32)
  // members_snapshot is read as a fixed-size 544 buffer; we need member_count_snapshot
  // (further down in the layout) to know how many slots are real. Read raw, decode after.
  const membersFlat = r.readBytes(MEMBERS_FLAT_SIZE)
  const amount = r.readU64LE()
  const expiresAt = r.readI64LE()
  const createdAt = r.readI64LE()
  const finalizedAt = r.readI64LE()
  const signatureScheme = r.readU16LE()
  const memberCountSnapshot = r.readU8()
  const thresholdSnapshot = r.readU8()
  const messageApprovalBump = r.readU8()
  const contributionsCount = r.readU8()
  const contributionsBitmap = r.readU16LE()

  const membersSnapshot: MemberSlotData[] = []
  for (let i = 0; i < memberCountSnapshot; i += 1) {
    const off = i * MEMBER_SLOT_LEN
    const slotRaw = membersFlat.slice(off, off + MEMBER_SLOT_LEN)
    const { scheme, identifier } = parseMemberSlot(slotRaw)
    membersSnapshot.push({ scheme, identifier, raw: slotRaw })
  }

  return {
    dwallet,
    policy,
    payerForClose,
    sessionNonce,
    messageDigest,
    metadataDigest,
    userPubkey,
    destination,
    membersSnapshot,
    amount,
    expiresAt,
    createdAt,
    finalizedAt,
    signatureScheme,
    memberCountSnapshot,
    thresholdSnapshot,
    messageApprovalBump,
    contributionsCount,
    contributionsBitmap,
  }
}

// ── Login Social — OidcJwtStaging (disc 4) ──────────────────────

export interface OidcJwtStagingAccountData {
  dwallet: Uint8Array
  policy: Uint8Array
  payerForClose: Uint8Array
  stagingNonce: bigint
  createdAt: bigint
  /** The staged compact JWT (`header.payload.signature` ASCII), `jwt_len` bytes. */
  jwt: Uint8Array
}

export function decodeOidcJwtStagingAccount(raw: Uint8Array): OidcJwtStagingAccountData {
  if (raw.length < ACCOUNT_DISCRIMINATOR_LEN + OIDC_JWT_STAGING_ACCOUNT_SIZE) {
    throw new Error(
      `OidcJwtStaging account too small: got ${raw.length}, need at least ${ACCOUNT_DISCRIMINATOR_LEN + OIDC_JWT_STAGING_ACCOUNT_SIZE}`,
    )
  }
  if (raw[0] !== OIDC_JWT_STAGING_ACCOUNT_DISCRIMINATOR) {
    throw new Error(`OidcJwtStaging discriminator mismatch: ${raw[0]}`)
  }
  const r = new ByteReader(raw.subarray(ACCOUNT_DISCRIMINATOR_LEN))
  const dwallet = r.readBytes(32)
  const policy = r.readBytes(32)
  const payerForClose = r.readBytes(32)
  const stagingNonce = r.readU64LE()
  const createdAt = r.readI64LE()
  const jwtLen = r.readU16LE()
  if (jwtLen > OIDC_JWT_BYTES_LEN) {
    throw new Error(`OidcJwtStaging jwt_len ${jwtLen} exceeds ${OIDC_JWT_BYTES_LEN}`)
  }
  const jwt = r.readBytes(jwtLen)
  r.skip(OIDC_JWT_BYTES_LEN - jwtLen)
  return { dwallet, policy, payerForClose, stagingNonce, createdAt, jwt }
}

// ── Login Social — OidcSession (disc 3) ─────────────────────────

export interface OidcSessionAccountData {
  dwallet: Uint8Array
  policy: Uint8Array
  payerForClose: Uint8Array
  jwkRegistry: Uint8Array
  /** `sha256("andromeda::oidc::addr::v1" || lp(iss) || lp(aud) || lp(sub))`. */
  addrSeed: Uint8Array
  /** The user's ephemeral Ed25519 public key (each use signs a per-use challenge). */
  ephPk: Uint8Array
  issuerHash: Uint8Array
  audienceHash: Uint8Array
  kidHash: Uint8Array
  sessionNonce: bigint
  nextUseNonce: bigint
  notAfterUnixTs: bigint
  expFromJwt: bigint
  /** `min(notAfter, min(exp, createdAt + SESSION_TTL))`. */
  expiresAt: bigint
  createdAt: bigint
  /** Reserved (always 0 — the session is GC'd on close). */
  closedAt: bigint
  oidcVerifierVersion: number
}

export function decodeOidcSessionAccount(raw: Uint8Array): OidcSessionAccountData {
  if (raw.length < ACCOUNT_DISCRIMINATOR_LEN + OIDC_SESSION_ACCOUNT_SIZE) {
    throw new Error(
      `OidcSession account too small: got ${raw.length}, need at least ${ACCOUNT_DISCRIMINATOR_LEN + OIDC_SESSION_ACCOUNT_SIZE}`,
    )
  }
  if (raw[0] !== OIDC_SESSION_ACCOUNT_DISCRIMINATOR) {
    throw new Error(`OidcSession discriminator mismatch: ${raw[0]}`)
  }
  const r = new ByteReader(raw.subarray(ACCOUNT_DISCRIMINATOR_LEN))
  const dwallet = r.readBytes(32)
  const policy = r.readBytes(32)
  const payerForClose = r.readBytes(32)
  const jwkRegistry = r.readBytes(32)
  const addrSeed = r.readBytes(OIDC_ADDR_SEED_LEN)
  const ephPk = r.readBytes(32)
  const issuerHash = r.readBytes(32)
  const audienceHash = r.readBytes(32)
  const kidHash = r.readBytes(32)
  const sessionNonce = r.readU64LE()
  const nextUseNonce = r.readU64LE()
  const notAfterUnixTs = r.readU64LE()
  const expFromJwt = r.readI64LE()
  const expiresAt = r.readI64LE()
  const createdAt = r.readI64LE()
  const closedAt = r.readI64LE()
  const oidcVerifierVersion = r.readU32LE()
  return {
    dwallet,
    policy,
    payerForClose,
    jwkRegistry,
    addrSeed,
    ephPk,
    issuerHash,
    audienceHash,
    kidHash,
    sessionNonce,
    nextUseNonce,
    notAfterUnixTs,
    expFromJwt,
    expiresAt,
    createdAt,
    closedAt,
    oidcVerifierVersion,
  }
}
