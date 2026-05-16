/**
 * Zero-copy decoders for PolicyEngine v3 account state.
 * Mirrors `contracts/policy-engine/src/lib.rs` and ABI §3.
 *
 * F2.7 status (2026-05-15): PolicyEngine header + RuleEntry index +
 * AllowlistRule. Other kinds (Velocity, TimeLock, Oracle, Passkey,
 * FheGated, SessionKey, Recovery) decode in F3..F9.
 */
import { address, getAddressDecoder, type Address } from '@solana/kit'
import { MAX_RULES, MEMBER_SLOT_LEN, type RuleKind } from './program.js'

const addrDecoder = getAddressDecoder()

function readU32LE(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset + off, 4).getUint32(0, true)
}

function readU64LE(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset + off, 8).getBigUint64(0, true)
}

// ── PolicyEngine header (ABI §3.1) ──────────────────────────────────────────

export interface RuleEntryView {
  kind: RuleKind
  bump: number
  version: number
  enabled: boolean
  generation: number
  rulePda: Address
  configHash: Uint8Array
}

export interface PolicyEngineState {
  accountDiscriminator: number
  version: number
  dwallet: Address
  initAuthoritySlot: Uint8Array
  ownerSlot: Uint8Array
  nextAdminNonce: bigint
  nextPrimaryRecoverNonce: bigint
  nextQuorumSessionNonce: bigint
  nextOidcSessionNonce: bigint
  nextPasskeySessionNonce: bigint
  paused: boolean
  rulesCount: number
  rulesGeneration: number
  rules: RuleEntryView[]
}

const RULE_ENTRY_BYTES = 96
const POLICY_ENGINE_MIN_BYTES =
  1 + 1 + 32 + MEMBER_SLOT_LEN + MEMBER_SLOT_LEN + 5 * 8 + 1 + 1 + 4 + 6 + MAX_RULES * RULE_ENTRY_BYTES + 8

export function decodePolicyEngine(data: Uint8Array): PolicyEngineState {
  if (data.length < POLICY_ENGINE_MIN_BYTES) {
    throw new Error(`policyEngine: account data too short (${data.length} < ${POLICY_ENGINE_MIN_BYTES})`)
  }
  if (data[0] !== 1) {
    throw new Error(`policyEngine: account discriminator = ${data[0]} (expected 1)`)
  }
  if (data[1] !== 1) {
    throw new Error(`policyEngine: unknown layout version = ${data[1]}`)
  }
  const dwallet = addrDecoder.decode(data.subarray(2, 34))
  const initAuthoritySlot = data.slice(34, 68)
  const ownerSlot = data.slice(68, 102)

  const rules: RuleEntryView[] = []
  for (let i = 0; i < MAX_RULES; i += 1) {
    const off = 154 + i * RULE_ENTRY_BYTES
    rules.push(decodeRuleEntry(data.subarray(off, off + RULE_ENTRY_BYTES)))
  }

  return {
    accountDiscriminator: data[0]!,
    version: data[1]!,
    dwallet,
    initAuthoritySlot,
    ownerSlot,
    nextAdminNonce: readU64LE(data, 102),
    nextPrimaryRecoverNonce: readU64LE(data, 110),
    nextQuorumSessionNonce: readU64LE(data, 118),
    nextOidcSessionNonce: readU64LE(data, 126),
    nextPasskeySessionNonce: readU64LE(data, 134),
    paused: data[142] === 1,
    rulesCount: data[143]!,
    rulesGeneration: readU32LE(data, 144),
    rules,
  }
}

function decodeRuleEntry(b: Uint8Array): RuleEntryView {
  const rulePda = addrDecoder.decode(b.subarray(8, 40))
  const configHash = b.slice(40, 72)
  return {
    kind: b[0]! as RuleKind,
    bump: b[1]!,
    version: b[2]!,
    enabled: b[3] === 1,
    generation: readU32LE(b, 4),
    rulePda,
    configHash,
  }
}

// ── AllowlistRule (ABI §3.4 header + §3.5.1 config) ────────────────────────

export interface AllowlistRuleState {
  accountDiscriminator: number
  kind: RuleKind
  index: number
  enabled: boolean
  generation: number
  configVersion: number
  engine: Address
  nextAdminNonce: bigint
  configHash: Uint8Array
  appliesTo: number
  destinationsCount: number
  destinations: Uint8Array[]
}

const ALLOWLIST_RULE_MIN_BYTES = 1 + 96 + 8 + 1024

export function decodeAllowlistRule(data: Uint8Array): AllowlistRuleState {
  if (data.length < ALLOWLIST_RULE_MIN_BYTES) {
    throw new Error(`AllowlistRule: data too short (${data.length} < ${ALLOWLIST_RULE_MIN_BYTES})`)
  }
  if (data[0] !== 2) {
    throw new Error(`AllowlistRule: discriminator = ${data[0]} (expected 2)`)
  }
  const engine = addrDecoder.decode(data.subarray(17, 49))
  const configHash = data.slice(57, 89)
  const destinationsCount = data[98]!
  const destinations: Uint8Array[] = []
  for (let i = 0; i < destinationsCount; i += 1) {
    const off = 105 + i * 32
    destinations.push(data.slice(off, off + 32))
  }
  return {
    accountDiscriminator: data[0]!,
    kind: data[1]! as RuleKind,
    index: data[2]!,
    enabled: data[3] === 1,
    generation: readU32LE(data, 5),
    configVersion: readU32LE(data, 9),
    engine,
    nextAdminNonce: readU64LE(data, 49),
    configHash,
    appliesTo: data[97]!,
    destinationsCount,
    destinations,
  }
}

// Silence the unused-import warning when `address` is only used via the decoder.
void address
