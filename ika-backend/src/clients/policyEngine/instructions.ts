/**
 * Typed instruction builders for PolicyEngine v3 (F2.4b).
 * Mirror of `gateway/internal/policy/ix_*.go`.
 *
 * F2.4b status (2026-05-15): `initEngine`, `addRuleAllowlist`,
 * `updateRuleAllowlistAddDestination`. `requestSignature` lands in
 * F2.6c when MessageApproval PDA + CPI authority bump resolution is wired.
 */
import { AccountRole, getAddressEncoder, type Address, type Instruction } from '@solana/kit'
import {
  eventAuthorityPda,
  passkeySessionPda,
  quorumSessionPda,
  rulePda,
  sessionPda,
} from './pda.js'
import {
  KIND_ALLOWLIST,
  KIND_FHE_GATED,
  KIND_RECOVERY,
  KIND_SESSION_KEY,
  POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR,
  MEMBER_SLOT_LEN,
  WEBAUTHN_AUTH_DATA_MAX,
  WEBAUTHN_CLIENT_DATA_JSON_MAX,
  type RuleKind,
} from './program.js'

// Local re-binds so the F8/F9 builders can use stable names even if program.ts
// re-exports change. Both are numeric literals — `K` suffix avoids unused
// import warnings.
const KIND_SESSION_KEY_K: RuleKind = KIND_SESSION_KEY
const KIND_RECOVERY_K: RuleKind = KIND_RECOVERY

const addrEncoder = getAddressEncoder()

export const SYSTEM_PROGRAM_ADDRESS = '11111111111111111111111111111111' as Address
export const SYSVAR_INSTRUCTIONS_ADDRESS =
  'Sysvar1nstructions1111111111111111111111111' as Address
export const SYSVAR_CLOCK_ADDRESS = 'SysvarC1ock11111111111111111111111111111111' as Address
export const SYSVAR_RENT_ADDRESS = 'SysvarRent111111111111111111111111111111111' as Address

interface AccountMeta {
  address: Address
  role: AccountRole
}

function makeIx(
  programAddress: Address,
  data: Uint8Array,
  accounts: AccountMeta[],
): Instruction {
  return { programAddress, accounts, data }
}

function u32LE(v: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, v, true)
  return b
}

function u64LE(v: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, v, true)
  return b
}

function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0
  for (const p of parts) len += p.length
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function assertLen(buf: Uint8Array, n: number, label: string): void {
  if (buf.length !== n) throw new Error(`${label} must be ${n} bytes (got ${buf.length})`)
}

// ── Disc 0 — init_engine ────────────────────────────────────────────────────

export interface InitEngineInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthoritySlot: Uint8Array // 34 bytes
  initAuthorityHash: Uint8Array // 32 bytes
  ownerSlot: Uint8Array // 34 bytes
  defaultRecoveryPresent: 0 | 1
  defaultRecoveryHash: Uint8Array // 32 bytes (zeroed when present === 0)
}

export async function buildInitEngineInstruction(input: InitEngineInput): Promise<Instruction> {
  if (input.defaultRecoveryPresent !== 0) {
    throw new Error('buildInitEngineInstruction: default_recovery_present=1 is F9 scope')
  }
  assertLen(input.initAuthoritySlot, MEMBER_SLOT_LEN, 'init_authority_slot')
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.ownerSlot, MEMBER_SLOT_LEN, 'owner_slot')
  assertLen(input.defaultRecoveryHash, 32, 'default_recovery_hash')

  const eventAuth = (await eventAuthorityPda(input.programId)).address

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.initEngine]),
    input.initAuthoritySlot,
    input.initAuthorityHash,
    input.ownerSlot,
    new Uint8Array([input.defaultRecoveryPresent]),
    input.defaultRecoveryHash,
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── Disc 10 — add_rule_allowlist ────────────────────────────────────────────

export interface AddRuleAllowlistInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array // 32 bytes
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
}

export async function buildAddRuleAllowlistInstruction(
  input: AddRuleAllowlistInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  if (input.ruleIndex < 0 || input.ruleIndex > 15)
    throw new Error(`rule_index out of range: ${input.ruleIndex}`)

  const rule = await rulePda(input.programId, input.engine, KIND_ALLOWLIST, input.ruleIndex)
  const eventAuth = await eventAuthorityPda(input.programId)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleAllowlist]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    new Uint8Array([input.appliesTo]),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule.address, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth.address, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── Disc 120 — update_rule_allowlist_add_destination ───────────────────────

export interface UpdateAllowlistAddDestinationInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  destination: Uint8Array // 32 bytes
}

export async function buildUpdateAllowlistAddDestinationInstruction(
  input: UpdateAllowlistAddDestinationInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.destination, 32, 'destination')

  const rule = await rulePda(input.programId, input.engine, KIND_ALLOWLIST, input.ruleIndex)
  const eventAuth = await eventAuthorityPda(input.programId)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleAllowlistAddDestination]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    input.destination,
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule.address, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth.address, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── Disc 11 — add_rule_velocity (F3) ────────────────────────────────────────

export interface VelocityWindow {
  windowSeconds: bigint
  cap: bigint
}

export interface AddRuleVelocityInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
  windows: VelocityWindow[] // 1..4 windows
}

export async function buildAddRuleVelocityInstruction(
  input: AddRuleVelocityInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  if (input.windows.length < 1 || input.windows.length > 4) {
    throw new Error(`velocity windows count must be 1..4 (got ${input.windows.length})`)
  }

  const windowsCfg = new Uint8Array(4 * 16)
  for (let i = 0; i < input.windows.length; i += 1) {
    const w = input.windows[i]!
    if (w.windowSeconds === 0n || w.cap === 0n) {
      throw new Error(`velocity window[${i}]: window_seconds and cap must be > 0`)
    }
    const dv = new DataView(windowsCfg.buffer, i * 16, 16)
    dv.setBigUint64(0, w.windowSeconds, true)
    dv.setBigUint64(8, w.cap, true)
  }

  const rule = await rulePda(input.programId, input.engine, 2, input.ruleIndex)
  const eventAuth = await eventAuthorityPda(input.programId)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleVelocity]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    new Uint8Array([input.appliesTo]),
    new Uint8Array([input.windows.length]),
    windowsCfg,
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule.address, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth.address, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── Disc 12 — add_rule_time_lock (F4) ───────────────────────────────────────

export const TIME_LOCK_MODE_ABSOLUTE = 0
export const TIME_LOCK_MODE_DELAY = 1

export interface AddRuleTimeLockInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
  mode: 0 | 1 // 0 absolute, 1 delay
  unlockTs: bigint
  delaySeconds: bigint
}

async function buildSimpleRuleAccounts(
  programId: Address,
  engine: Address,
  dwallet: Address,
  payer: Address,
  ruleKind: number,
  ruleIndex: number,
): Promise<AccountMeta[]> {
  const rule = await rulePda(programId, engine, ruleKind as 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8, ruleIndex)
  const eventAuth = await eventAuthorityPda(programId)
  return [
    { address: dwallet, role: AccountRole.READONLY },
    { address: engine, role: AccountRole.WRITABLE },
    { address: rule.address, role: AccountRole.WRITABLE },
    { address: payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth.address, role: AccountRole.READONLY },
    { address: programId, role: AccountRole.READONLY },
  ]
}

function i64LE(v: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigInt64(0, v, true)
  return b
}

export async function buildAddRuleTimeLockInstruction(
  input: AddRuleTimeLockInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  if (input.mode !== 0 && input.mode !== 1) {
    throw new Error(`time-lock mode must be 0 or 1 (got ${input.mode})`)
  }
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleTimeLock]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex, input.appliesTo, input.mode]),
    i64LE(input.unlockTs),
    u64LE(input.delaySeconds),
  ])
  return makeIx(
    input.programId,
    data,
    await buildSimpleRuleAccounts(input.programId, input.engine, input.dwallet, input.payer, 3, input.ruleIndex),
  )
}

// ── Disc 13 — add_rule_oracle (F5) ──────────────────────────────────────────

export interface AddRuleOracleInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
  freshnessSecondsDiv16: number
  minConfidenceBpsDiv4: number
}

export async function buildAddRuleOracleInstruction(
  input: AddRuleOracleInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleOracle]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([
      input.ruleIndex,
      input.appliesTo,
      input.freshnessSecondsDiv16,
      input.minConfidenceBpsDiv4,
    ]),
  ])
  return makeIx(
    input.programId,
    data,
    await buildSimpleRuleAccounts(input.programId, input.engine, input.dwallet, input.payer, 4, input.ruleIndex),
  )
}

// ── Disc 14 — add_rule_passkey (F6) ─────────────────────────────────────────

export interface AddRulePasskeyInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
}

export async function buildAddRulePasskeyInstruction(
  input: AddRulePasskeyInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRulePasskey]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex, input.appliesTo]),
  ])
  return makeIx(
    input.programId,
    data,
    await buildSimpleRuleAccounts(input.programId, input.engine, input.dwallet, input.payer, 5, input.ruleIndex),
  )
}

// ── Disc 15 — add_rule_fhe_gated (F7) ───────────────────────────────────────

export interface AddRuleFheGatedInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number
  freshnessSecondsDiv16: number
}

export async function buildAddRuleFheGatedInstruction(
  input: AddRuleFheGatedInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleFheGated]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex, input.appliesTo, input.freshnessSecondsDiv16]),
  ])
  return makeIx(
    input.programId,
    data,
    await buildSimpleRuleAccounts(input.programId, input.engine, input.dwallet, input.payer, 6, input.ruleIndex),
  )
}

// ── Disc 126 — update_rule_fhe_gated_authorities (C2 audit fix) ─────────────
//
// `add_rule_fhe_gated` (disc 15) initialises the FHE rule with
// `authorities_count = 0`; the dispatch fail-closes on count == 0. Disc 126
// replaces the entire authority list in one shot. Owner signs an
// `update-rule-fhe-authorities` admin challenge binding the new state.

export const MAX_FHE_AUTHORITIES = 4

export interface UpdateRuleFheGatedAuthoritiesInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  newCount: number
  // `newAuthorities` is the full 128-byte canonical slot. Trailing slots
  // beyond `newCount` MUST be zero — the on-chain handler hashes the full
  // 128 B into `config_hash`.
  newAuthorities: Uint8Array
}

export async function buildUpdateRuleFheGatedAuthoritiesInstruction(
  input: UpdateRuleFheGatedAuthoritiesInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.newAuthorities, MAX_FHE_AUTHORITIES * 32, 'new_authorities')
  if (
    !Number.isInteger(input.newCount) ||
    input.newCount < 1 ||
    input.newCount > MAX_FHE_AUTHORITIES
  ) {
    throw new Error(`fhe authorities count out of [1..=${MAX_FHE_AUTHORITIES}]: ${input.newCount}`)
  }
  const rule = (await rulePda(input.programId, input.engine, KIND_FHE_GATED, input.ruleIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleFheGatedAuthorities]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex, input.newCount]),
    input.newAuthorities,
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── Disc 1 — request_signature ──────────────────────────────────────────────

export interface RequestSignatureInput {
  programId: Address
  dwallet: Address
  engine: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthority: Address
  callerProgram: Address // MUST NOT equal `programId` — see F2.5b bug note.
  dwalletProgram: Address // Ika program id (87W54k…).
  // F8a: one sub-PDA per active rule slot, in ascending slot order. Empty
  // array is valid when the engine has zero active rules. Each PDA is
  // attached as WRITABLE so kinds with mutable counters (Velocity,
  // SessionKey, Recovery) can write back via `data_ptr()`.
  rulePdas: Address[]
  initAuthorityHash: Uint8Array // 32 bytes
  messageDigest: Uint8Array // 32 bytes
  metadataDigest: Uint8Array // 32 bytes
  userPubkey: Uint8Array // 32 bytes
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  destination: Uint8Array // 32 bytes
  rulesGenerationSeen: number
  /** Update 3 (ABI V2): asset amount in base units. Default 0n. */
  amount?: bigint
  /** Update 3 (ABI V2): index in the KIND_SPENDING_USD allowlist. Default 0. */
  assetIndex?: number
  /**
   * Update 6 (ABI V3): the Ika message_metadata_digest (32 bytes) forwarded to
   * approve_message. Default = 32 zero bytes (no signing metadata; the prior
   * behaviour for every chain except Zcash). For Zcash pass keccak256 of the
   * BCS Blake2bMessageMetadata (from prepare-message). The MessageApproval PDA
   * must be derived with the matching metadata seed when non-zero.
   */
  ikaMsgMetadataDigest?: Uint8Array
}

export async function buildRequestSignatureInstruction(
  input: RequestSignatureInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  assertLen(input.destination, 32, 'destination')
  if (input.callerProgram === input.programId) {
    throw new Error(
      'caller_program must NOT equal programId — quasar-svm flags duplicates as AccountBorrowFailed (F2.5b)',
    )
  }

  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const scheme = new Uint8Array(2)
  new DataView(scheme.buffer).setUint16(0, input.signatureScheme, true)
  const gen = u32LE(input.rulesGenerationSeen)
  const ikaMsgMetadataDigest = input.ikaMsgMetadataDigest ?? new Uint8Array(32)
  assertLen(ikaMsgMetadataDigest, 32, 'ika_msg_metadata_digest')

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.requestSignature]),
    input.initAuthorityHash,
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    scheme,
    new Uint8Array([input.messageApprovalBump, input.cpiAuthorityBump]),
    input.destination,
    gen,
    // ABI V2 (Update 3): amount (u64 LE) + asset_index (u8).
    u64LE(input.amount ?? 0n),
    new Uint8Array([input.assetIndex ?? 0]),
    // ABI V3 (Update 6): the Ika message_metadata_digest (32 bytes; zero = none).
    ikaMsgMetadataDigest,
  ])

  const accounts = [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthority, role: AccountRole.READONLY },
    { address: input.callerProgram, role: AccountRole.READONLY },
    { address: input.dwalletProgram, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ]
  for (const pda of input.rulePdas) {
    accounts.push({ address: pda, role: AccountRole.WRITABLE })
  }
  return makeIx(input.programId, data, accounts)
}

// ── F8b — add_rule_session_key (disc 16) ──────────────────────────────────

export interface AddRuleSessionKeyInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array // 32 bytes
  expectedNonce: bigint
  ruleIndex: number
  appliesTo: number // MUST equal APPLIES_SESSION (=4)
  maxSessions: number
  defaultTtlSeconds: bigint
  defaultMaxUses: number
  sessionMaxAmountPerTx: bigint
}

export async function buildAddRuleSessionKeyInstruction(
  input: AddRuleSessionKeyInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const rule = (await rulePda(input.programId, input.engine, KIND_SESSION_KEY_K, input.ruleIndex))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleSessionKey]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex, input.appliesTo, input.maxSessions]),
    u64LE(input.defaultTtlSeconds),
    u32LE(input.defaultMaxUses),
    u64LE(input.sessionMaxAmountPerTx),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── F8b — session_open (disc 100) ────────────────────────────────────────

export interface SessionOpenInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  sessionIndex: number
  sessionSigner: Address // session keypair pubkey
  expiresAtTs: bigint    // signed unix seconds; encoded as u64 LE
  maxUses: number
  maxAmountPerTx: bigint
}

export async function buildSessionOpenInstruction(input: SessionOpenInput): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const rule = (await rulePda(input.programId, input.engine, KIND_SESSION_KEY_K, input.ruleIndex))
    .address
  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const signerBytes = addrEncoder.encode(input.sessionSigner)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionOpen]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    u32LE(input.sessionIndex),
    new Uint8Array(signerBytes),
    u64LE(input.expiresAtTs),
    u32LE(input.maxUses),
    u64LE(input.maxAmountPerTx),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.READONLY },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── F8b — request_signature_via_session (disc 101) ───────────────────────

export interface RequestSignatureViaSessionInput {
  programId: Address
  dwallet: Address
  engine: Address
  sessionSigner: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthority: Address
  callerProgram: Address // MUST NOT equal `programId` — see F2.5b bug note.
  dwalletProgram: Address
  initAuthorityHash: Uint8Array
  sessionIndex: number
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  destination: Uint8Array
  expectedSignatureNonce: bigint
}

export async function buildRequestSignatureViaSessionInstruction(
  input: RequestSignatureViaSessionInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  assertLen(input.destination, 32, 'destination')
  if (input.callerProgram === input.programId) {
    throw new Error(
      'caller_program must NOT equal programId — quasar-svm flags duplicates as AccountBorrowFailed (F2.5b)',
    )
  }

  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const scheme = new Uint8Array(2)
  new DataView(scheme.buffer).setUint16(0, input.signatureScheme, true)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.requestSignatureViaSession]),
    input.initAuthorityHash,
    u32LE(input.sessionIndex),
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    scheme,
    new Uint8Array([input.messageApprovalBump, input.cpiAuthorityBump]),
    input.destination,
    u64LE(input.expectedSignatureNonce),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.sessionSigner, role: AccountRole.READONLY_SIGNER },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthority, role: AccountRole.READONLY },
    { address: input.callerProgram, role: AccountRole.READONLY },
    { address: input.dwalletProgram, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── F8c — session lifecycle (revoke / close / cleanup / dest updates) ─────

function sessionAdminAccounts(
  programId: Address,
  dwallet: Address,
  engine: Address,
  session: Address,
  payer: Address,
  eventAuth: Address,
): AccountMeta[] {
  return [
    { address: dwallet, role: AccountRole.READONLY },
    { address: engine, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: payer, role: AccountRole.WRITABLE_SIGNER },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: programId, role: AccountRole.READONLY },
  ]
}

function sessionCloseAccounts(
  programId: Address,
  dwallet: Address,
  engine: Address,
  session: Address,
  recipient: Address,
  payer: Address,
  eventAuth: Address,
): AccountMeta[] {
  return [
    { address: dwallet, role: AccountRole.READONLY },
    { address: engine, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: recipient, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: payer, role: AccountRole.WRITABLE_SIGNER },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: programId, role: AccountRole.READONLY },
  ]
}

export interface SessionRevokeInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  sessionIndex: number
  expectedNonce: bigint
}

export async function buildSessionRevokeInstruction(
  input: SessionRevokeInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionRevoke]),
    input.initAuthorityHash,
    u32LE(input.sessionIndex),
    u64LE(input.expectedNonce),
  ])
  return makeIx(
    input.programId,
    data,
    sessionAdminAccounts(input.programId, input.dwallet, input.engine, session, input.payer, eventAuth),
  )
}

export interface SessionCloseInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  recipient: Address
  initAuthorityHash: Uint8Array
  sessionIndex: number
  expectedNonce: bigint
}

export async function buildSessionCloseInstruction(
  input: SessionCloseInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionClose]),
    input.initAuthorityHash,
    u32LE(input.sessionIndex),
    u64LE(input.expectedNonce),
  ])
  return makeIx(
    input.programId,
    data,
    sessionCloseAccounts(
      input.programId,
      input.dwallet,
      input.engine,
      session,
      input.recipient,
      input.payer,
      eventAuth,
    ),
  )
}

export interface CloseExpiredSessionInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  recipient: Address
  initAuthorityHash: Uint8Array
  sessionIndex: number
}

export async function buildCloseExpiredSessionInstruction(
  input: CloseExpiredSessionInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.closeExpiredSession]),
    input.initAuthorityHash,
    u32LE(input.sessionIndex),
  ])
  return makeIx(
    input.programId,
    data,
    sessionCloseAccounts(
      input.programId,
      input.dwallet,
      input.engine,
      session,
      input.recipient,
      input.payer,
      eventAuth,
    ),
  )
}

export interface SessionDestinationInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  sessionIndex: number
  expectedNonce: bigint
  destination: Uint8Array // 32 bytes
}

async function buildSessionDestinationIx(
  disc: number,
  input: SessionDestinationInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.destination, 32, 'destination')
  const session = (await sessionPda(input.programId, input.engine, input.sessionIndex)).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([disc]),
    input.initAuthorityHash,
    u32LE(input.sessionIndex),
    u64LE(input.expectedNonce),
    input.destination,
  ])
  return makeIx(
    input.programId,
    data,
    sessionAdminAccounts(input.programId, input.dwallet, input.engine, session, input.payer, eventAuth),
  )
}

export function buildSessionAddDestinationInstruction(
  input: SessionDestinationInput,
): Promise<Instruction> {
  return buildSessionDestinationIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionAddDestination,
    input,
  )
}

export function buildSessionRemoveDestinationInstruction(
  input: SessionDestinationInput,
): Promise<Instruction> {
  return buildSessionDestinationIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionRemoveDestination,
    input,
  )
}

// ── F9a — Recovery rule updates + recover_as_primary ─────────────────────

function recoveryUpdateAccounts(
  programId: Address,
  dwallet: Address,
  engine: Address,
  rule: Address,
  payer: Address,
  eventAuth: Address,
): AccountMeta[] {
  return [
    { address: dwallet, role: AccountRole.READONLY },
    { address: engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: programId, role: AccountRole.READONLY },
  ]
}

export interface UpdateRecoveryMemberInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  memberSlot: Uint8Array // 34 bytes
}

async function buildRecoveryMemberIx(
  disc: number,
  input: UpdateRecoveryMemberInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.memberSlot, MEMBER_SLOT_LEN, 'member_slot')
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([disc]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    input.memberSlot,
  ])
  return makeIx(
    input.programId,
    data,
    recoveryUpdateAccounts(input.programId, input.dwallet, input.engine, rule, input.payer, eventAuth),
  )
}

export function buildUpdateRecoveryAddMemberInstruction(
  input: UpdateRecoveryMemberInput,
): Promise<Instruction> {
  return buildRecoveryMemberIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryAddMember,
    input,
  )
}

export function buildUpdateRecoveryRemoveMemberInstruction(
  input: UpdateRecoveryMemberInput,
): Promise<Instruction> {
  return buildRecoveryMemberIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryRemoveMember,
    input,
  )
}

export interface UpdateRecoveryDestinationInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  expectedNonce: bigint
  ruleIndex: number
  destination: Uint8Array // 32 bytes
}

async function buildRecoveryDestinationIx(
  disc: number,
  input: UpdateRecoveryDestinationInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.destination, 32, 'destination')
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([disc]),
    input.initAuthorityHash,
    u64LE(input.expectedNonce),
    new Uint8Array([input.ruleIndex]),
    input.destination,
  ])
  return makeIx(
    input.programId,
    data,
    recoveryUpdateAccounts(input.programId, input.dwallet, input.engine, rule, input.payer, eventAuth),
  )
}

export function buildUpdateRecoveryAddDestinationInstruction(
  input: UpdateRecoveryDestinationInput,
): Promise<Instruction> {
  return buildRecoveryDestinationIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryAddDestination,
    input,
  )
}

export function buildUpdateRecoveryRemoveDestinationInstruction(
  input: UpdateRecoveryDestinationInput,
): Promise<Instruction> {
  return buildRecoveryDestinationIx(
    POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryRemoveDestination,
    input,
  )
}

export interface RecoverAsPrimaryInput {
  programId: Address
  dwallet: Address
  engine: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthority: Address
  callerProgram: Address // MUST NOT equal `programId`
  dwalletProgram: Address
  initAuthorityHash: Uint8Array
  ruleIndex: number
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  destination: Uint8Array
  expectedNonce: bigint
  amount: bigint
}

export async function buildRecoverAsPrimaryInstruction(
  input: RecoverAsPrimaryInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  assertLen(input.destination, 32, 'destination')
  if (input.callerProgram === input.programId) {
    throw new Error(
      'caller_program must NOT equal programId — quasar-svm flags duplicates as AccountBorrowFailed (F2.5b)',
    )
  }
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const scheme = new Uint8Array(2)
  new DataView(scheme.buffer).setUint16(0, input.signatureScheme, true)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.recoverAsPrimary]),
    input.initAuthorityHash,
    new Uint8Array([input.ruleIndex]),
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    scheme,
    new Uint8Array([input.messageApprovalBump, input.cpiAuthorityBump]),
    input.destination,
    u64LE(input.expectedNonce),
    u64LE(input.amount),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthority, role: AccountRole.READONLY },
    { address: input.callerProgram, role: AccountRole.READONLY },
    { address: input.dwalletProgram, role: AccountRole.READONLY },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── F9b — Quorum recovery (open / contribute / finalize / close) ─────────

export interface QuorumSessionOpenInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  ruleIndex: number
  sessionNonce: bigint
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  amount: bigint
  destination: Uint8Array
  expiresAt: bigint // signed unix seconds; encoded as u64 LE
}

export async function buildQuorumSessionOpenInstruction(
  input: QuorumSessionOpenInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  assertLen(input.destination, 32, 'destination')
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex))
    .address
  const session = (await quorumSessionPda(input.programId, input.engine, input.sessionNonce))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const scheme = new Uint8Array(2)
  new DataView(scheme.buffer).setUint16(0, input.signatureScheme, true)
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.quorumSessionOpen]),
    input.initAuthorityHash,
    new Uint8Array([input.ruleIndex]),
    u64LE(input.sessionNonce),
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    scheme,
    new Uint8Array([input.messageApprovalBump]),
    u64LE(input.amount),
    input.destination,
    u64LE(input.expiresAt),
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

export interface QuorumSessionContributeInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  sessionNonce: bigint
  memberIndex: number
}

export async function buildQuorumSessionContributeInstruction(
  input: QuorumSessionContributeInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (await quorumSessionPda(input.programId, input.engine, input.sessionNonce))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.quorumSessionContribute]),
    input.initAuthorityHash,
    u64LE(input.sessionNonce),
    new Uint8Array([input.memberIndex]),
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// `ruleIndex` added by audit fix H1 (2026-05-16): on-chain Accts struct no
// longer hardcodes `rule_index = 0`. Callers MUST pass the same `ruleIndex`
// used when the session was opened.
export interface QuorumSessionFinalizeInput {
  programId: Address
  dwallet: Address
  engine: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthority: Address
  callerProgram: Address
  dwalletProgram: Address
  initAuthorityHash: Uint8Array
  ruleIndex: number
  sessionNonce: bigint
  cpiAuthorityBump: number
}

export async function buildQuorumSessionFinalizeInstruction(
  input: QuorumSessionFinalizeInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const rule = (
    await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex)
  ).address
  const session = (await quorumSessionPda(input.programId, input.engine, input.sessionNonce))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.quorumSessionFinalize]),
    input.initAuthorityHash,
    new Uint8Array([input.ruleIndex]),
    u64LE(input.sessionNonce),
    new Uint8Array([input.cpiAuthorityBump]),
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthority, role: AccountRole.READONLY },
    { address: input.callerProgram, role: AccountRole.READONLY },
    { address: input.dwalletProgram, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

export interface QuorumSessionCloseInput {
  programId: Address
  dwallet: Address
  engine: Address
  /** Receives the rent refund AND signs the tx. MUST equal
   *  `session.payer_for_close` (locked in at open time). */
  recipient: Address
  initAuthorityHash: Uint8Array
  sessionNonce: bigint
}

export async function buildQuorumSessionCloseInstruction(
  input: QuorumSessionCloseInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (await quorumSessionPda(input.programId, input.engine, input.sessionNonce))
    .address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.quorumSessionClose]),
    input.initAuthorityHash,
    u64LE(input.sessionNonce),
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.READONLY },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.recipient, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

// ── F9d — Passkey recovery (open / use / close) ──────────────────────────

export interface PasskeySessionOpenInput {
  programId: Address
  dwallet: Address
  engine: Address
  payer: Address
  initAuthorityHash: Uint8Array
  ruleIndex: number
  passkeySessionNonce: bigint
  ephPk: Uint8Array // 32 bytes
  notAfterUnixTs: bigint
  credentialIdHash: Uint8Array // 32 bytes
  expectedPasskeySessionNonce: bigint
  webauthnAuthData: Uint8Array // 1..=WEBAUTHN_AUTH_DATA_MAX
  webauthnClientDataJson: Uint8Array // 1..=WEBAUTHN_CLIENT_DATA_JSON_MAX
}

export async function buildPasskeySessionOpenInstruction(
  input: PasskeySessionOpenInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.ephPk, 32, 'eph_pk')
  assertLen(input.credentialIdHash, 32, 'credential_id_hash')
  if (input.webauthnAuthData.length === 0 || input.webauthnAuthData.length > WEBAUTHN_AUTH_DATA_MAX) {
    throw new Error(
      `webauthn_auth_data length ${input.webauthnAuthData.length} out of [1..=${WEBAUTHN_AUTH_DATA_MAX}]`,
    )
  }
  if (
    input.webauthnClientDataJson.length === 0 ||
    input.webauthnClientDataJson.length > WEBAUTHN_CLIENT_DATA_JSON_MAX
  ) {
    throw new Error(
      `webauthn_client_data_json length ${input.webauthnClientDataJson.length} out of [1..=${WEBAUTHN_CLIENT_DATA_JSON_MAX}]`,
    )
  }
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex))
    .address
  const session = (
    await passkeySessionPda(input.programId, input.engine, input.passkeySessionNonce)
  ).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address

  const authPadded = new Uint8Array(WEBAUTHN_AUTH_DATA_MAX)
  authPadded.set(input.webauthnAuthData)
  const cdjPadded = new Uint8Array(WEBAUTHN_CLIENT_DATA_JSON_MAX)
  cdjPadded.set(input.webauthnClientDataJson)
  const authLen = new Uint8Array(2)
  new DataView(authLen.buffer).setUint16(0, input.webauthnAuthData.length, true)
  const cdjLen = new Uint8Array(2)
  new DataView(cdjLen.buffer).setUint16(0, input.webauthnClientDataJson.length, true)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.passkeySessionOpen]),
    input.initAuthorityHash,
    new Uint8Array([input.ruleIndex]),
    u64LE(input.passkeySessionNonce),
    input.ephPk,
    u64LE(input.notAfterUnixTs),
    input.credentialIdHash,
    u64LE(input.expectedPasskeySessionNonce),
    authLen,
    authPadded,
    cdjLen,
    cdjPadded,
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.WRITABLE },
    { address: session, role: AccountRole.WRITABLE },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_RENT_ADDRESS, role: AccountRole.READONLY },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

export interface RecoverAsPrimaryPasskeySessionInput {
  programId: Address
  dwallet: Address
  engine: Address
  coordinator: Address
  messageApproval: Address
  payer: Address
  cpiAuthority: Address
  callerProgram: Address
  dwalletProgram: Address
  initAuthorityHash: Uint8Array
  // H2 audit fix (2026-05-16): rule_index is now part of the wire format.
  // Must match the slot the RecoveryRule was created at.
  ruleIndex: number
  passkeySessionNonce: bigint
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  messageApprovalBump: number
  cpiAuthorityBump: number
  expectedUseNonce: bigint
}

export async function buildRecoverAsPrimaryPasskeySessionInstruction(
  input: RecoverAsPrimaryPasskeySessionInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  assertLen(input.messageDigest, 32, 'message_digest')
  assertLen(input.metadataDigest, 32, 'metadata_digest')
  assertLen(input.userPubkey, 32, 'user_pubkey')
  if (!Number.isInteger(input.ruleIndex) || input.ruleIndex < 0 || input.ruleIndex > 15) {
    throw new Error(`rule_index out of [0..15]: ${input.ruleIndex}`)
  }
  const rule = (await rulePda(input.programId, input.engine, KIND_RECOVERY_K, input.ruleIndex)).address
  const session = (
    await passkeySessionPda(input.programId, input.engine, input.passkeySessionNonce)
  ).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const scheme = new Uint8Array(2)
  new DataView(scheme.buffer).setUint16(0, input.signatureScheme, true)

  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.recoverAsPrimaryPasskeySession]),
    input.initAuthorityHash,
    new Uint8Array([input.ruleIndex]),
    u64LE(input.passkeySessionNonce),
    input.messageDigest,
    input.metadataDigest,
    input.userPubkey,
    scheme,
    new Uint8Array([input.messageApprovalBump, input.cpiAuthorityBump]),
    u64LE(input.expectedUseNonce),
  ])

  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.WRITABLE },
    { address: rule, role: AccountRole.READONLY },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.coordinator, role: AccountRole.READONLY },
    { address: input.messageApproval, role: AccountRole.WRITABLE },
    { address: input.payer, role: AccountRole.WRITABLE_SIGNER },
    { address: input.cpiAuthority, role: AccountRole.READONLY },
    { address: input.callerProgram, role: AccountRole.READONLY },
    { address: input.dwalletProgram, role: AccountRole.READONLY },
    { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

export interface PasskeySessionCloseInput {
  programId: Address
  dwallet: Address
  engine: Address
  recipient: Address // signs + receives rent (MUST == session.payer_for_close)
  initAuthorityHash: Uint8Array
  passkeySessionNonce: bigint
}

export async function buildPasskeySessionCloseInstruction(
  input: PasskeySessionCloseInput,
): Promise<Instruction> {
  assertLen(input.initAuthorityHash, 32, 'init_authority_hash')
  const session = (
    await passkeySessionPda(input.programId, input.engine, input.passkeySessionNonce)
  ).address
  const eventAuth = (await eventAuthorityPda(input.programId)).address
  const data = concat([
    new Uint8Array([POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.passkeySessionClose]),
    input.initAuthorityHash,
    u64LE(input.passkeySessionNonce),
  ])
  return makeIx(input.programId, data, [
    { address: input.dwallet, role: AccountRole.READONLY },
    { address: input.engine, role: AccountRole.READONLY },
    { address: session, role: AccountRole.WRITABLE },
    { address: input.recipient, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSVAR_CLOCK_ADDRESS, role: AccountRole.READONLY },
    { address: eventAuth, role: AccountRole.READONLY },
    { address: input.programId, role: AccountRole.READONLY },
  ])
}

void addrEncoder
void ((kind: RuleKind) => kind)
