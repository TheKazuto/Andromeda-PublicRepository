/**
 * Canonical challenge encoders for PolicyEngine v3 (clear-signing v2).
 *
 * Mirrors `contracts/policy-engine/src/lib.rs` byte-for-byte. The Rust
 * `admin_challenge` / `request_metadata_digest` helpers and these functions
 * MUST stay in sync — cross-language fixtures in
 * `fixtures/policy_engine_v3/challenges/` are the contract.
 */
import { createHash } from 'node:crypto'
import { getAddressEncoder, type Address } from '@solana/kit'
import { MEMBER_SLOT_LEN } from './program.js'
import { formatAmountPlain } from '../../format/amount.js'

/**
 * Canonical decimal shift for monetary values in signed human messages (oracle
 * price bounds, USD spending caps — 1e8 base units). MUST mirror byte-for-byte
 * `VALUE_DECIMALS_1E8` (Rust auth) + `humanfmt.ValueDecimals1e8` (Go) + the
 * Python fixture generator. Changing it is an ABI break (Update 6 M2b).
 */
const VALUE_DECIMALS_1E8 = 8

const enc = new TextEncoder()
const addrEncoder = getAddressEncoder()

// ── Domains (ABI §6.1) ────────────────────────────────────────────────────

export const DOMAIN_INIT_V1 = enc.encode('andromeda::policy-engine::init::v1')
export const DOMAIN_V3 = enc.encode('andromeda::policy-engine::v3')
export const DOMAIN_REQUEST_V1 = enc.encode('andromeda::policy-engine::request::v1')
// Update 3: V2 binds amount + asset_index for KIND_SPENDING_USD.
export const DOMAIN_REQUEST_V2 = enc.encode('andromeda::policy-engine::request::v2')
export const DOMAIN_RECOVERY_V3 = enc.encode('andromeda::policy-engine::recovery::v3')

// ── Op tags (ABI §6.3) ────────────────────────────────────────────────────

export const OP_INIT = enc.encode('init')
export const OP_INIT_WITH_RECOVERY = enc.encode('init-with-recovery')
export const OP_ADD_ALLOWLIST = enc.encode('add-rule-allowlist')
export const OP_ALLOWLIST_ADD_DEST = enc.encode('allowlist-add-destination')
export const OP_ALLOWLIST_REMOVE_DEST = enc.encode('allowlist-remove-destination')
export const OP_ADD_SPENDING_USD = enc.encode('add-rule-spending-usd')
export const OP_SPENDING_USD_ADD_FEED = enc.encode('spending-usd-add-feed')
export const OP_PAUSE = enc.encode('pause')
export const OP_RESUME = enc.encode('resume')
export const OP_REVOKE = enc.encode('revoke')

// ── Helpers ───────────────────────────────────────────────────────────────

function u16LE(v: number): Uint8Array {
  if (v < 0 || v > 0xffff) throw new Error(`u16 out of range: ${v}`)
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, v, true)
  return b
}

function u32LE(v: number): Uint8Array {
  if (v < 0 || v > 0xffffffff) throw new Error(`u32 out of range: ${v}`)
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

function sha256Bytes(input: Uint8Array): Uint8Array {
  const h = createHash('sha256')
  h.update(input)
  return new Uint8Array(h.digest())
}

function hexLower(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 1) s += b[i]!.toString(16).padStart(2, '0')
  return s
}

// ── Init challenge (ABI §6.1) ─────────────────────────────────────────────
//
// Mirror of `contracts/policy-engine/src/lib.rs::policy_engine_init_challenge`.
// The init_authority signs this hash off-chain; `init_engine` recomputes it
// from the typed params and rejects any mismatch via the Ed25519 precompile.

export interface PolicyEngineInitChallengeInput {
  dwallet: Address
  initAuthoritySlot: Uint8Array // 34 bytes
  ownerSlot: Uint8Array // 34 bytes
  /** 0 = init plain, 1 = init-with-recovery (binds defaultRecoveryHash). */
  defaultRecoveryPresent: 0 | 1
  /** Reserved for F11: hash of the default RecoveryRule config when
   *  `defaultRecoveryPresent === 1`. Pass 32 zero bytes for plain init. */
  defaultRecoveryHash: Uint8Array // 32 bytes
}

export function policyEngineInitChallengePreimage(
  input: PolicyEngineInitChallengeInput,
): Uint8Array {
  if (input.initAuthoritySlot.length !== MEMBER_SLOT_LEN) {
    throw new Error(
      `initAuthoritySlot must be ${MEMBER_SLOT_LEN} bytes, got ${input.initAuthoritySlot.length}`,
    )
  }
  if (input.ownerSlot.length !== MEMBER_SLOT_LEN) {
    throw new Error(`ownerSlot must be ${MEMBER_SLOT_LEN} bytes, got ${input.ownerSlot.length}`)
  }
  if (input.defaultRecoveryHash.length !== 32) {
    throw new Error(
      `defaultRecoveryHash must be 32 bytes, got ${input.defaultRecoveryHash.length}`,
    )
  }
  const opTag =
    input.defaultRecoveryPresent === 1
      ? enc.encode('init-with-recovery')
      : OP_INIT
  return concat([
    DOMAIN_INIT_V1,
    opTag,
    new Uint8Array(addrEncoder.encode(input.dwallet)),
    input.initAuthoritySlot,
    input.ownerSlot,
    new Uint8Array([input.defaultRecoveryPresent]),
    input.defaultRecoveryHash,
  ])
}

export function policyEngineInitChallenge(
  input: PolicyEngineInitChallengeInput,
): Uint8Array {
  return sha256Bytes(policyEngineInitChallengePreimage(input))
}

// ── Admin challenge (ABI §6.2) ────────────────────────────────────────────

export interface AdminChallengeInput {
  opTag: Uint8Array
  humanMessage: Uint8Array
  engine: Address
  dwallet: Address
  ruleKind: number
  ruleIndex: number
  ruleGeneration: number
  expectedNonce: bigint
  configHash: Uint8Array // 32 bytes
  ownerSlot: Uint8Array // 34 bytes
  extras: Uint8Array[]
}

export function adminChallengePreimage(input: AdminChallengeInput): Uint8Array {
  if (input.configHash.length !== 32)
    throw new Error(`configHash must be 32 bytes, got ${input.configHash.length}`)
  if (input.ownerSlot.length !== MEMBER_SLOT_LEN)
    throw new Error(`ownerSlot must be ${MEMBER_SLOT_LEN} bytes, got ${input.ownerSlot.length}`)
  if (input.humanMessage.length > 0xffff)
    throw new Error(`humanMessage > u16 max (${input.humanMessage.length} bytes)`)

  const parts: Uint8Array[] = [
    DOMAIN_V3,
    input.opTag,
    u16LE(input.humanMessage.length),
    input.humanMessage,
    new Uint8Array(addrEncoder.encode(input.engine)),
    new Uint8Array(addrEncoder.encode(input.dwallet)),
    new Uint8Array([input.ruleKind]),
    new Uint8Array([input.ruleIndex]),
    u32LE(input.ruleGeneration),
    u64LE(input.expectedNonce),
    input.configHash,
    input.ownerSlot,
  ]
  // M2 audit fix (2026-05-16): each extra is prefixed with u16 LE length so
  // two variable-length extras can't be silently concatenated into an
  // ambiguous byte string. Mirror of `admin_challenge` in
  // contracts/policy-engine/src/lib.rs.
  for (const e of input.extras) {
    if (e.length > 0xffff) {
      throw new Error(`admin extra > u16 max (${e.length} bytes)`)
    }
    parts.push(u16LE(e.length))
    parts.push(e)
  }
  return concat(parts)
}

export function adminChallengeHash(input: AdminChallengeInput): Uint8Array {
  return sha256Bytes(adminChallengePreimage(input))
}

// ── Runtime request_metadata_digest (ABI §6.4) ────────────────────────────

export interface RequestMetadataDigestInput {
  engine: Address
  dwallet: Address
  messageDigest: Uint8Array // 32 bytes
  destination: Uint8Array // 32 bytes
  userPubkey: Uint8Array // 32 bytes
  signatureScheme: number
  path: number // APPLIES_NORMAL / APPLIES_RECOVERY / APPLIES_SESSION
  rulesGeneration: number
  /** Update 3 (ABI V2): asset amount in base units. Default 0n. */
  amount?: bigint
  /** Update 3 (ABI V2): index in the KIND_SPENDING_USD allowlist. Default 0. */
  assetIndex?: number
}

export function requestMetadataDigestPreimage(input: RequestMetadataDigestInput): Uint8Array {
  if (input.messageDigest.length !== 32) throw new Error('messageDigest must be 32 bytes')
  if (input.destination.length !== 32) throw new Error('destination must be 32 bytes')
  if (input.userPubkey.length !== 32) throw new Error('userPubkey must be 32 bytes')

  return concat([
    DOMAIN_REQUEST_V2,
    enc.encode('request-signature'),
    new Uint8Array(addrEncoder.encode(input.engine)),
    new Uint8Array(addrEncoder.encode(input.dwallet)),
    input.messageDigest,
    input.destination,
    input.userPubkey,
    u16LE(input.signatureScheme),
    new Uint8Array([input.path]),
    u32LE(input.rulesGeneration),
    u64LE(input.amount ?? 0n),
    new Uint8Array([input.assetIndex ?? 0]),
  ])
}

export function requestMetadataDigest(input: RequestMetadataDigestInput): Uint8Array {
  return sha256Bytes(requestMetadataDigestPreimage(input))
}

// ── Allowlist config_hash ─────────────────────────────────────────────────

export function allowlistConfigHash(
  appliesTo: number,
  destinationsCount: number,
  destinationsFlat: Uint8Array,
): Uint8Array {
  if (destinationsFlat.length !== 1024)
    throw new Error(`destinationsFlat must be 1024 bytes, got ${destinationsFlat.length}`)
  return sha256Bytes(
    concat([
      enc.encode('allowlist-config-v1'),
      new Uint8Array([appliesTo]),
      new Uint8Array([destinationsCount]),
      destinationsFlat,
    ]),
  )
}

// ── SpendingUsd config_hash (Update 3) ────────────────────────────────────

export const SPENDING_USD_FEED_BYTES = 33
export const MAX_SPENDING_USD_FEEDS = 16

export function spendingUsdConfigHash(
  appliesTo: number,
  feedsCount: number,
  freshnessSecondsDiv16: number,
  maxConfidenceBpsDiv4: number,
  maxPerTx: bigint,
  maxPerDay: bigint,
  maxPerWeek: bigint,
  feedsFlat: Uint8Array,
): Uint8Array {
  if (feedsFlat.length !== MAX_SPENDING_USD_FEEDS * SPENDING_USD_FEED_BYTES)
    throw new Error(
      `feedsFlat must be ${MAX_SPENDING_USD_FEEDS * SPENDING_USD_FEED_BYTES} bytes, got ${feedsFlat.length}`,
    )
  return sha256Bytes(
    concat([
      enc.encode('spending-usd-config-v1'),
      new Uint8Array([appliesTo, feedsCount, freshnessSecondsDiv16, maxConfidenceBpsDiv4]),
      u64LE(maxPerTx),
      u64LE(maxPerDay),
      u64LE(maxPerWeek),
      feedsFlat,
    ]),
  )
}

// ── Human-message renderers ───────────────────────────────────────────────
//
// Mirror of `contracts/auth/src/human_message.rs`. Any drift produces a
// different challenge hash and rejects the signature.

export function humanMessageSpendingUsdAdd(
  maxPerTx: bigint,
  maxPerDay: bigint,
  maxPerWeek: bigint,
  engine: Address,
  dwallet: Address,
): Uint8Array {
  return enc.encode(
    `Add USD spending limit policy ${engine} for dWallet ${dwallet} maxPerTx ${formatAmountPlain(maxPerTx, VALUE_DECIMALS_1E8)} maxPerDay ${formatAmountPlain(maxPerDay, VALUE_DECIMALS_1E8)} maxPerWeek ${formatAmountPlain(maxPerWeek, VALUE_DECIMALS_1E8)}`,
  )
}

export function humanMessageSpendingUsdAddFeed(
  feedCache: Address,
  decimals: number,
  engine: Address,
  dwallet: Address,
): Uint8Array {
  return enc.encode(
    `Add spending feed ${feedCache} decimals ${decimals} on USD spending policy ${engine} for dWallet ${dwallet}`,
  )
}

export function humanMessageAllowlistAddDestination(
  dest: Uint8Array,
  engine: Address,
  dwallet: Address,
): Uint8Array {
  if (dest.length !== 32) throw new Error('dest must be 32 bytes')
  return enc.encode(
    `Allow destination ${hexLower(dest)} on allowlist policy ${engine} for dWallet ${dwallet}`,
  )
}

export function humanMessageAllowlistRemoveDestination(
  dest: Uint8Array,
  engine: Address,
  dwallet: Address,
): Uint8Array {
  if (dest.length !== 32) throw new Error('dest must be 32 bytes')
  return enc.encode(
    `Block destination ${hexLower(dest)} on allowlist policy ${engine} for dWallet ${dwallet}`,
  )
}

export function humanMessageAllowlistPause(engine: Address, dwallet: Address): Uint8Array {
  return enc.encode(`Pause allowlist policy ${engine} for dWallet ${dwallet}`)
}

export function humanMessageAllowlistResume(engine: Address, dwallet: Address): Uint8Array {
  return enc.encode(`Resume allowlist policy ${engine} for dWallet ${dwallet}`)
}
