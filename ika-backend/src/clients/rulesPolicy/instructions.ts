/**
 * Instruction builders for `contracts/rules-policy/src/lib.rs` (v2 +
 * Audit C1/C2/C3).
 *
 * Audit C1: `current_ts` and `current_slot` are NO LONGER in the wire —
 * the on-chain handler reads them from the Clock sysvar. Every Accounts
 * struct that needs them carries `pub clock: Sysvar<Clock>` so this
 * client must include `SYSVAR_CLOCK_ADDRESS` in the meta slice.
 *
 * Audit C2 (Opção 4): every instruction except the bootstrap arg list
 * carries `init_authority_hash: [u8; 32]` as the FIRST argument so Quasar
 * can derive the policy PDA from `[b"rules_policy", dwallet, hash]`.
 * `init_policy` additionally carries the full 34-byte `init_authority_slot`
 * (the precompile signature over the canonical init challenge is added
 * upstream by the caller).
 */

import { AccountRole, type Address, type Instruction } from '@solana/kit'
import { ByteWriter } from './codecs.js'
import {
  MAX_JWT_LEN,
  MAX_MEMBERS,
  MEMBER_SLOT_LEN,
  RULES_POLICY_INSTRUCTION_DISCRIMINATOR,
  WEBAUTHN_AUTH_DATA_MAX,
  WEBAUTHN_CLIENT_DATA_JSON_MAX,
} from './program.js'

export const SYSTEM_PROGRAM_ADDRESS = '11111111111111111111111111111111' as Address
export const SYSVAR_RENT_ADDRESS = 'SysvarRent111111111111111111111111111111111' as Address
export const SYSVAR_INSTRUCTIONS_ADDRESS =
  'Sysvar1nstructions1111111111111111111111111' as Address
export const SYSVAR_CLOCK_ADDRESS =
  'SysvarC1ock11111111111111111111111111111111' as Address

interface AccountMeta {
  address: Address
  role: AccountRole
}

function ix(programAddress: Address, data: Uint8Array, accounts: AccountMeta[]): Instruction {
  return {
    programAddress,
    accounts: accounts.map((a) => ({ address: a.address, role: a.role })),
    data,
  }
}

function assertLen(input: Uint8Array, n: number, label: string): void {
  if (input.length !== n) throw new Error(`${label} must be ${n} bytes (got ${input.length})`)
}

function memberIndexesArray(indexes: Uint8Array): Uint8Array {
  if (indexes.length > MAX_MEMBERS) {
    throw new Error(`member indexes count exceeds MAX_MEMBERS=${MAX_MEMBERS}`)
  }
  const out = new Uint8Array(MAX_MEMBERS)
  out.set(indexes)
  return out
}
// keep referenced symbol alive even if no caller uses it currently
void memberIndexesArray

function padded(buf: Uint8Array, n: number, label: string): Uint8Array {
  if (buf.length > n) throw new Error(`${label} length ${buf.length} exceeds max ${n}`)
  if (buf.length === n) return buf
  const out = new Uint8Array(n)
  out.set(buf)
  return out
}

function assertHash(initAuthorityHash: Uint8Array): void {
  assertLen(initAuthorityHash, 32, 'init_authority_hash')
}

// ── 0. init_policy ─────────────────────────────────────────────

export function buildInitPolicyInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  payer: Address
  eventAuthorityPda: Address
  initAuthoritySlot: Uint8Array
  initAuthorityHash: Uint8Array
  primarySlot: Uint8Array
  quorumThreshold: number
  dailyLimitSome: boolean
  dailyLimit: bigint
  cooldownSeconds: bigint
  allowedDestinationsSome: boolean
}): Instruction {
  assertLen(input.initAuthoritySlot, MEMBER_SLOT_LEN, 'init_authority_slot')
  assertHash(input.initAuthorityHash)
  assertLen(input.primarySlot, MEMBER_SLOT_LEN, 'primary_slot')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.initPolicy)
  w.writeBytes(input.initAuthoritySlot)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.primarySlot)
  w.writeU8(input.quorumThreshold)
  w.writeU8(input.dailyLimitSome ? 1 : 0)
  w.writeU64LE(input.dailyLimit)
  w.writeU64LE(input.cooldownSeconds)
  w.writeU8(input.allowedDestinationsSome ? 1 : 0)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 1. recover_as_primary ──────────────────────────────────────

export function buildRecoverAsPrimaryInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthorityPda: Address
  ikaProgramId: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.recoverAsPrimary)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.messageDigest)
  w.writeBytes(input.metadataDigest)
  w.writeBytes(input.userPubkey)
  w.writeU16LE(input.signatureScheme)
  w.writeU8(input.messageApprovalBump)
  w.writeU8(input.cpiAuthorityBump)
  w.writeU64LE(input.expectedNonce)

  // NOTE: no separate `caller_program` slot — the contract reuses `program`
  // as the Ika CPI caller (passing this program twice triggers AccountBorrowFailed).
  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthorityPda, role: AccountRole.READONLY },
    { address: input.ikaProgramId, role: AccountRole.READONLY },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 2. quorum_session_open ─────────────────────────────────────

export function buildQuorumSessionOpenInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  payer: Address
  initAuthorityHash: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  amount: bigint
  destination: Uint8Array
  expiresAt: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  assertLen(input.destination, 32, 'destination')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.quorumSessionOpen)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.messageDigest)
  w.writeBytes(input.metadataDigest)
  w.writeBytes(input.userPubkey)
  w.writeU16LE(input.signatureScheme)
  w.writeU8(input.messageApprovalBump)
  w.writeU64LE(input.amount)
  w.writeBytes(input.destination)
  w.writeI64LE(input.expiresAt)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ── 3. quorum_session_contribute ───────────────────────────────

export function buildQuorumSessionContributeInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  payer: Address
  initAuthorityHash: Uint8Array
  memberIndex: number
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.quorumSessionContribute)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.memberIndex)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
  ])
}

// ── 4. quorum_session_contribute_webauthn ──────────────────────

export function buildQuorumSessionContributeWebauthnInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  payer: Address
  initAuthorityHash: Uint8Array
  memberIndex: number
  webauthnAuthData: Uint8Array
  webauthnClientDataJson: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)
  if (input.webauthnAuthData.length > WEBAUTHN_AUTH_DATA_MAX) {
    throw new Error(`webauthn_auth_data exceeds ${WEBAUTHN_AUTH_DATA_MAX} bytes`)
  }
  if (input.webauthnClientDataJson.length > WEBAUTHN_CLIENT_DATA_JSON_MAX) {
    throw new Error(`webauthn_client_data_json exceeds ${WEBAUTHN_CLIENT_DATA_JSON_MAX} bytes`)
  }

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.quorumSessionContributeWebauthn)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.memberIndex)
  w.writeU8(input.webauthnAuthData.length)
  w.writeBytes(padded(input.webauthnAuthData, WEBAUTHN_AUTH_DATA_MAX, 'webauthn_auth_data'))
  w.writeU16LE(input.webauthnClientDataJson.length)
  w.writeBytes(padded(input.webauthnClientDataJson, WEBAUTHN_CLIENT_DATA_JSON_MAX, 'webauthn_cdj'))

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
  ])
}

// ── 5. quorum_session_finalize ─────────────────────────────────

export function buildQuorumSessionFinalizeInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthorityPda: Address
  ikaProgramId: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  cpiAuthorityBump: number
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.quorumSessionFinalize)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.cpiAuthorityBump)

  // NOTE: no separate `caller_program` slot — see buildRecoverAsPrimaryInstruction.
  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthorityPda, role: AccountRole.READONLY },
    { address: input.ikaProgramId, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 6. quorum_session_close ────────────────────────────────────

export function buildQuorumSessionCloseInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  rentDestination: Address
  initAuthorityHash: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.quorumSessionClose)
  w.writeBytes(input.initAuthorityHash)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.rentDestination, role: AccountRole.WRITABLE },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ── 7-18: AdminAction-shaped instructions ──────────────────────

interface AdminActionAccounts {
  programId: Address
  policyPda: Address
  dwallet: Address
  payer: Address
  initAuthorityHash: Uint8Array
}

function adminAccounts(input: AdminActionAccounts): AccountMeta[] {
  return [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
  ]
}

function buildAdminMemberSlotIx(
  discriminator: number,
  base: AdminActionAccounts,
  memberSlot: Uint8Array,
  expectedNonce: bigint,
): Instruction {
  assertHash(base.initAuthorityHash)
  assertLen(memberSlot, MEMBER_SLOT_LEN, 'member_slot')
  const w = new ByteWriter()
  w.writeU8(discriminator)
  w.writeBytes(base.initAuthorityHash)
  w.writeBytes(memberSlot)
  w.writeU64LE(expectedNonce)
  return ix(base.programId, w.toUint8Array(), adminAccounts(base))
}

function buildAdminAddressIx(
  discriminator: number,
  base: AdminActionAccounts,
  destination: Uint8Array,
  expectedNonce: bigint,
): Instruction {
  assertHash(base.initAuthorityHash)
  assertLen(destination, 32, 'destination')
  const w = new ByteWriter()
  w.writeU8(discriminator)
  w.writeBytes(base.initAuthorityHash)
  w.writeBytes(destination)
  w.writeU64LE(expectedNonce)
  return ix(base.programId, w.toUint8Array(), adminAccounts(base))
}

export function buildAddMemberInstruction(input: AdminActionAccounts & {
  newMemberSlot: Uint8Array
  expectedNonce: bigint
}): Instruction {
  return buildAdminMemberSlotIx(
    RULES_POLICY_INSTRUCTION_DISCRIMINATOR.addMember,
    input,
    input.newMemberSlot,
    input.expectedNonce,
  )
}

export function buildRemoveMemberInstruction(input: AdminActionAccounts & {
  memberSlotToRemove: Uint8Array
  expectedNonce: bigint
}): Instruction {
  return buildAdminMemberSlotIx(
    RULES_POLICY_INSTRUCTION_DISCRIMINATOR.removeMember,
    input,
    input.memberSlotToRemove,
    input.expectedNonce,
  )
}

export function buildAddDestinationInstruction(input: AdminActionAccounts & {
  destination: Uint8Array
  expectedNonce: bigint
}): Instruction {
  return buildAdminAddressIx(
    RULES_POLICY_INSTRUCTION_DISCRIMINATOR.addDestination,
    input,
    input.destination,
    input.expectedNonce,
  )
}

export function buildRemoveDestinationInstruction(input: AdminActionAccounts & {
  destination: Uint8Array
  expectedNonce: bigint
}): Instruction {
  return buildAdminAddressIx(
    RULES_POLICY_INSTRUCTION_DISCRIMINATOR.removeDestination,
    input,
    input.destination,
    input.expectedNonce,
  )
}

export function buildRevokeInstruction(input: AdminActionAccounts & {
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.revoke)
  w.writeBytes(input.initAuthorityHash)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildSetPrimaryInstruction(input: AdminActionAccounts & {
  newPrimarySlot: Uint8Array
  expectedNonce: bigint
}): Instruction {
  return buildAdminMemberSlotIx(
    RULES_POLICY_INSTRUCTION_DISCRIMINATOR.setPrimary,
    input,
    input.newPrimarySlot,
    input.expectedNonce,
  )
}

export function buildSetQuorumThresholdImmediateInstruction(input: AdminActionAccounts & {
  newThreshold: number
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.setQuorumThresholdImmediate)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.newThreshold)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildSetDailyLimitImmediateInstruction(input: AdminActionAccounts & {
  newSome: boolean
  newLimit: bigint
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.setDailyLimitImmediate)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.newSome ? 1 : 0)
  w.writeU64LE(input.newLimit)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildSetCooldownImmediateInstruction(input: AdminActionAccounts & {
  newCooldownSeconds: bigint
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.setCooldownImmediate)
  w.writeBytes(input.initAuthorityHash)
  w.writeU64LE(input.newCooldownSeconds)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildProposeQuorumThresholdChangeInstruction(input: AdminActionAccounts & {
  newThreshold: number
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.proposeQuorumThresholdChange)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.newThreshold)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildProposeDailyLimitChangeInstruction(input: AdminActionAccounts & {
  newSome: boolean
  newLimit: bigint
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.proposeDailyLimitChange)
  w.writeBytes(input.initAuthorityHash)
  w.writeU8(input.newSome ? 1 : 0)
  w.writeU64LE(input.newLimit)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

export function buildProposeCooldownChangeInstruction(input: AdminActionAccounts & {
  newCooldownSeconds: bigint
  expectedNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.proposeCooldownChange)
  w.writeBytes(input.initAuthorityHash)
  w.writeU64LE(input.newCooldownSeconds)
  w.writeU64LE(input.expectedNonce)
  return ix(input.programId, w.toUint8Array(), adminAccounts(input))
}

// ── 19. apply_pending_change ───────────────────────────────────

export function buildApplyPendingChangeInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  initAuthorityHash: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.applyPendingChange)
  w.writeBytes(input.initAuthorityHash)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ════════════════════════════════════════════════════════════════
// Login Social — `scheme = 4 = OidcJwt` (disc 20..=24)
//
// Mirrors `contracts/rules-policy/src/lib.rs` (Fase 3b). See loginsocial.md
// §7.4. A dWallet with an OIDC primary recovers only via these instructions —
// the challenge-based flows (`recover_as_primary`, quorum, admin) reject
// scheme 4.
// ════════════════════════════════════════════════════════════════

// ── 20. oidc_jwt_stage ─────────────────────────────────────────
//
// Wire layout: `[disc(1)][init_authority_hash(32)][jwt_len(u16 LE)][jwt_bytes]`
// — Quasar `#[max(4096, pfx = 2)] jwt_bytes: &[u8]` desugars to a 2-byte LE
// length prefix in the compact-instruction header followed by the bytes.

export function buildOidcJwtStageInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  stagingPda: Address
  payer: Address
  initAuthorityHash: Uint8Array
  /** The compact JWT `header.payload.signature` (ASCII), 1..=MAX_JWT_LEN bytes. */
  jwt: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)
  if (input.jwt.length === 0 || input.jwt.length > MAX_JWT_LEN) {
    throw new Error(`jwt must be 1..=${MAX_JWT_LEN} bytes (got ${input.jwt.length})`)
  }

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.oidcJwtStage)
  w.writeBytes(input.initAuthorityHash)
  w.writeU16LE(input.jwt.length)
  w.writeBytes(input.jwt)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.stagingPda, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ── 21. oidc_session_open ──────────────────────────────────────

export function buildOidcSessionOpenInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  stagingPda: Address
  jwkRegistry: Address
  sessionPda: Address
  /** Receives the staging account's rent refund — must equal `staging.payer_for_close`. */
  stagingPayer: Address
  payer: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  ephPk: Uint8Array
  notAfterUnixTs: bigint
  nonceRandomness: Uint8Array
  oidcVerifierVersion: number
  /** Bump of the canonical `JwkRegistry` PDA (`[b"jwk_registry", [0u8;32]]`). */
  jwkRegistryBump: number
  issuerHash: Uint8Array
  audienceHash: Uint8Array
  kidHash: Uint8Array
  /**
   * Policy's `next_oidc_session_nonce` observed by the client off-chain (the
   * same value baked into the signed `oidc_session_open_challenge`). The
   * program rejects with `InvalidNonce` if the on-chain value has advanced —
   * see audit F-1 (`docs/AUDIT_LOGINSOCIAL_2026_05.md`, 2026-05-13).
   */
  expectedSessionNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.ephPk, 32, 'eph_pk')
  assertLen(input.nonceRandomness, 32, 'nonce_randomness')
  assertLen(input.issuerHash, 32, 'issuer_hash')
  assertLen(input.audienceHash, 32, 'audience_hash')
  assertLen(input.kidHash, 32, 'kid_hash')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.oidcSessionOpen)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.ephPk)
  w.writeU64LE(input.notAfterUnixTs)
  w.writeBytes(input.nonceRandomness)
  w.writeU32LE(input.oidcVerifierVersion)
  w.writeU8(input.jwkRegistryBump)
  w.writeBytes(input.issuerHash)
  w.writeBytes(input.audienceHash)
  w.writeBytes(input.kidHash)
  w.writeU64LE(input.expectedSessionNonce)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.stagingPda, role: AccountRole.WRITABLE },
    { address: input.jwkRegistry, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.stagingPayer, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 22. recover_as_primary_oidc_session ────────────────────────

export function buildRecoverAsPrimaryOidcSessionInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  jwkRegistry: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthorityPda: Address
  ikaProgramId: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  expectedUseNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.recoverAsPrimaryOidcSession)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.messageDigest)
  w.writeBytes(input.metadataDigest)
  w.writeBytes(input.userPubkey)
  w.writeU16LE(input.signatureScheme)
  w.writeU8(input.messageApprovalBump)
  w.writeU8(input.cpiAuthorityBump)
  w.writeU64LE(input.expectedUseNonce)

  // NOTE: no separate `caller_program` slot — the contract reuses `program`
  // as the Ika CPI caller (see buildRecoverAsPrimaryInstruction).
  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.jwkRegistry, role: AccountRole.READONLY },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthorityPda, role: AccountRole.READONLY },
    { address: input.ikaProgramId, role: AccountRole.READONLY },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 23. oidc_session_close ─────────────────────────────────────

export function buildOidcSessionCloseInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  rentDestination: Address
  initAuthorityHash: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.oidcSessionClose)
  w.writeBytes(input.initAuthorityHash)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.rentDestination, role: AccountRole.WRITABLE },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ── 24. oidc_jwt_staging_close ─────────────────────────────────

export function buildOidcJwtStagingCloseInstruction(input: {
  programId: Address
  stagingPda: Address
  rentDestination: Address
}): Instruction {
  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.oidcJwtStagingClose)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.stagingPda, role: AccountRole.WRITABLE },
    { address: input.rentDestination, role: AccountRole.WRITABLE },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
  ])
}

// ── 25. passkey_session_open (Keyspring Fase 2 — D1 Opção A) ────

export function buildPasskeySessionOpenInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  payer: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  ephPk: Uint8Array
  notAfterUnixTs: bigint
  credentialIdHash: Uint8Array
  /** `policy.next_passkey_session_nonce` observed by the client (mirrors OIDC F-1 reject-fast). */
  expectedSessionNonce: bigint
  /** `authenticatorData` from the WebAuthn assertion (≤ 192 bytes — D13). */
  webauthnAuthData: Uint8Array
  /** `clientDataJSON` from the WebAuthn assertion (≤ 192 bytes). */
  webauthnClientDataJson: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.ephPk, 32, 'eph_pk')
  assertLen(input.credentialIdHash, 32, 'credential_id_hash')
  if (input.webauthnAuthData.length === 0 || input.webauthnAuthData.length > 192) {
    throw new Error(`webauthn_auth_data must be 1..=192 bytes (got ${input.webauthnAuthData.length})`)
  }
  if (input.webauthnClientDataJson.length === 0 || input.webauthnClientDataJson.length > 192) {
    throw new Error(
      `webauthn_client_data_json must be 1..=192 bytes (got ${input.webauthnClientDataJson.length})`,
    )
  }

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.passkeySessionOpen)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.ephPk)
  w.writeU64LE(input.notAfterUnixTs)
  w.writeBytes(input.credentialIdHash)
  w.writeU64LE(input.expectedSessionNonce)
  // Two `#[max(192, pfx = 2)]` slices — u16 length-prefix in LE then payload.
  w.writeU16LE(input.webauthnAuthData.length)
  w.writeBytes(input.webauthnAuthData)
  w.writeU16LE(input.webauthnClientDataJson.length)
  w.writeBytes(input.webauthnClientDataJson)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.WRITABLE },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 26. recover_as_primary_passkey_session (Keyspring Fase 2) ───

export function buildRecoverAsPrimaryPasskeySessionInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthorityPda: Address
  ikaProgramId: Address
  eventAuthorityPda: Address
  initAuthorityHash: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  expectedUseNonce: bigint
}): Instruction {
  assertHash(input.initAuthorityHash)
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.recoverAsPrimaryPasskeySession)
  w.writeBytes(input.initAuthorityHash)
  w.writeBytes(input.messageDigest)
  w.writeBytes(input.metadataDigest)
  w.writeBytes(input.userPubkey)
  w.writeU16LE(input.signatureScheme)
  w.writeU8(input.messageApprovalBump)
  w.writeU8(input.cpiAuthorityBump)
  w.writeU64LE(input.expectedUseNonce)

  // Account order mirrors `RecoverAsPrimaryPasskeySession` in lib.rs (no
  // jwk_registry — passkey assertion is self-contained, unlike OIDC).
  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthorityPda, role: AccountRole.READONLY },
    { address: input.ikaProgramId, role: AccountRole.READONLY },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: input.eventAuthorityPda, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── 27. passkey_session_close (Keyspring Fase 2) ────────────────

export function buildPasskeySessionCloseInstruction(input: {
  programId: Address
  policyPda: Address
  dwallet: Address
  sessionPda: Address
  rentDestination: Address
  initAuthorityHash: Uint8Array
}): Instruction {
  assertHash(input.initAuthorityHash)

  const w = new ByteWriter()
  w.writeU8(RULES_POLICY_INSTRUCTION_DISCRIMINATOR.passkeySessionClose)
  w.writeBytes(input.initAuthorityHash)

  return ix(input.programId, w.toUint8Array(), [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.policyPda, role: AccountRole.READONLY },
    { address: input.sessionPda, role: AccountRole.WRITABLE },
    { address: input.rentDestination, role: AccountRole.WRITABLE },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
  ])
}
