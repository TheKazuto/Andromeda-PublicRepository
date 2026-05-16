// Decoders for Andromeda policy template account state.
//
// ⚠️ AUDIT 2026-05 STATUS — STILL ON v1 LAYOUT:
//
// The decoders below describe the v1 ABI (pre-Audit 2026-05). The hand-written
// templates under `contracts/<name>/` were migrated to v2: state header gained
// `owner_slot[34]`, `init_authority_slot[34]`, `next_admin_nonce: u64`, and
// `paused` shrank from `u64` to `u8`. Oracle gained `max_confidence_bps: u16`
// (Audit M1). Every decoder here must be updated before reading state from a
// v2-deployed program — otherwise field offsets are wrong.
//
// Production code does NOT use these decoders today. Recovery routes call
// `adapter.readStateByHash(...)` which goes through the SolanaAdapter (which
// is already v2-aware). These decoders are kept for unit tests and for any
// future GET endpoint that needs to read a policy's full state — at that
// point migrate to v2 layouts referencing `contracts/<template>/src/lib.rs`
// and `gateway/internal/policies/registry.go::Layout`.
//
// Layout reference for v1 (validated historically against devnet):
//
//   TimeLockPolicy (discriminator 1, 105 bytes):
//     [0]      u8           discriminator (= 1)
//     [1..33]  Address      dwallet
//     [33..65] Address      owner
//     [65..73] u64 LE       start_slot
//     [73..81] u64 LE       end_slot
//     [81..89] u64 LE       recurring_period_slots
//     [89..97] u64 LE       mode (0 = absolute, 1 = recurring)
//     [97..105] u64 LE      paused (0 = active, 1 = paused)

import {
  address as toAddress,
  getAddressDecoder,
  type Address,
} from '@solana/kit';

const addrDecoder = getAddressDecoder();

const DISC_TIME_LOCK = 1;
const DISC_ALLOWLIST = 1;
const DISC_VELOCITY = 1;
const DISC_SESSION_KEYS = 1;
const DISC_ORACLE = 1;
const DISC_PASSKEY = 1;
const DISC_FHE_GATED = 1;

// ── TimeLockPolicy ──────────────────────────────────────────────────────

export interface TimeLockPolicyState {
  dwallet: Address;
  owner: Address;
  startSlot: bigint;
  endSlot: bigint;
  recurringPeriodSlots: bigint;
  mode: 'absolute' | 'recurring';
  paused: boolean;
}

export function decodeTimeLockPolicy(raw: Uint8Array): TimeLockPolicyState {
  if (raw.length < 105) {
    throw new Error(`TimeLockPolicy too small: got ${raw.length}, want >= 105`);
  }
  if (raw[0] !== DISC_TIME_LOCK) {
    throw new Error(`TimeLockPolicy discriminator mismatch: got ${raw[0]}, want ${DISC_TIME_LOCK}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const dwallet = addrDecoder.decode(raw.subarray(1, 33)) as Address;
  const owner = addrDecoder.decode(raw.subarray(33, 65)) as Address;
  const startSlot = view.getBigUint64(65, true);
  const endSlot = view.getBigUint64(73, true);
  const recurringPeriodSlots = view.getBigUint64(81, true);
  const modeRaw = view.getBigUint64(89, true);
  const pausedRaw = view.getBigUint64(97, true);
  return {
    dwallet,
    owner,
    startSlot,
    endSlot,
    recurringPeriodSlots,
    mode: modeRaw === 0n ? 'absolute' : 'recurring',
    paused: pausedRaw !== 0n,
  };
}

// ── AllowlistPolicy ─────────────────────────────────────────────────────
//
//   [0]      u8                     discriminator (= 1)
//   [1..33]  Address                dwallet
//   [33..65] Address                owner
//   [65]     u8                     paused (1 byte; spec also allows u64 — we
//                                   read 1 byte for compatibility with the
//                                   tighter-packed AllowlistPolicy struct)
//   [66]     u8                     destinations_count
//   [67..1091] [u8; 1024]           destinations_flat (32 × 32 bytes)
//
// Total: 1091 bytes.

export interface AllowlistPolicyState {
  dwallet: Address;
  owner: Address;
  paused: boolean;
  destinations: Address[];
}

export function decodeAllowlistPolicy(raw: Uint8Array): AllowlistPolicyState {
  if (raw.length < 1091) {
    throw new Error(`AllowlistPolicy too small: got ${raw.length}, want >= 1091`);
  }
  if (raw[0] !== DISC_ALLOWLIST) {
    throw new Error(`AllowlistPolicy discriminator mismatch: ${raw[0]}`);
  }
  const dwallet = addrDecoder.decode(raw.subarray(1, 33)) as Address;
  const owner = addrDecoder.decode(raw.subarray(33, 65)) as Address;
  const paused = raw[65] !== 0;
  const count = raw[66] ?? 0;
  const destinations: Address[] = [];
  for (let i = 0; i < count; i += 1) {
    const off = 67 + i * 32;
    destinations.push(addrDecoder.decode(raw.subarray(off, off + 32)) as Address);
  }
  return { dwallet, owner, paused, destinations };
}

// ── VelocityPolicy ──────────────────────────────────────────────────────
//
//   [0]       u8         discriminator (= 1)
//   [1..33]   Address    dwallet
//   [33..65]  Address    owner
//   [65]      u8         paused
//   [66..70]  u32 LE     max_sigs_per_window
//   [70..78]  u64 LE     window_slots
//   [78..82]  u32 LE     current_count
//   [82..90]  u64 LE     window_start_slot
//
// Total: 90 bytes.

export interface VelocityPolicyState {
  dwallet: Address;
  owner: Address;
  paused: boolean;
  maxSigsPerWindow: number;
  windowSlots: bigint;
  currentCount: number;
  windowStartSlot: bigint;
}

export function decodeVelocityPolicy(raw: Uint8Array): VelocityPolicyState {
  if (raw.length < 90) {
    throw new Error(`VelocityPolicy too small: got ${raw.length}, want >= 90`);
  }
  if (raw[0] !== DISC_VELOCITY) {
    throw new Error(`VelocityPolicy discriminator mismatch: ${raw[0]}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  return {
    dwallet: addrDecoder.decode(raw.subarray(1, 33)) as Address,
    owner: addrDecoder.decode(raw.subarray(33, 65)) as Address,
    paused: raw[65] !== 0,
    maxSigsPerWindow: view.getUint32(66, true),
    windowSlots: view.getBigUint64(70, true),
    currentCount: view.getUint32(78, true),
    windowStartSlot: view.getBigUint64(82, true),
  };
}

// ── SessionKeyPolicy ────────────────────────────────────────────────────
//
//   [0]       u8           discriminator (= 1)
//   [1..33]   Address      dwallet
//   [33..65]  Address      owner
//   [65..97]  Address      session_key
//   [97..105] u64 LE       expires_at_slot
//   [105..113] u64 LE      max_amount_per_tx
//   [113..117] u32 LE      used_count
//   [117..121] u32 LE      max_uses
//   [121]     u8           allowed_program_count
//   [122..378] [u8; 256]   allowed_programs_flat (8 × 32)
//
// Total: 378 bytes.

export interface SessionKeyPolicyState {
  dwallet: Address;
  owner: Address;
  sessionKey: Address;
  expiresAtSlot: bigint;
  maxAmountPerTx: bigint;
  usedCount: number;
  maxUses: number;
  allowedPrograms: Address[];
}

export function decodeSessionKeyPolicy(raw: Uint8Array): SessionKeyPolicyState {
  if (raw.length < 378) {
    throw new Error(`SessionKeyPolicy too small: got ${raw.length}, want >= 378`);
  }
  if (raw[0] !== DISC_SESSION_KEYS) {
    throw new Error(`SessionKeyPolicy discriminator mismatch: ${raw[0]}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const count = raw[121] ?? 0;
  const allowedPrograms: Address[] = [];
  for (let i = 0; i < count; i += 1) {
    const off = 122 + i * 32;
    allowedPrograms.push(addrDecoder.decode(raw.subarray(off, off + 32)) as Address);
  }
  return {
    dwallet: addrDecoder.decode(raw.subarray(1, 33)) as Address,
    owner: addrDecoder.decode(raw.subarray(33, 65)) as Address,
    sessionKey: addrDecoder.decode(raw.subarray(65, 97)) as Address,
    expiresAtSlot: view.getBigUint64(97, true),
    maxAmountPerTx: view.getBigUint64(105, true),
    usedCount: view.getUint32(113, true),
    maxUses: view.getUint32(117, true),
    allowedPrograms,
  };
}

// ── OraclePolicy ────────────────────────────────────────────────────────

export interface OraclePolicyState {
  dwallet: Address;
  owner: Address;
  oracleFeed: Address;
  minPrice: bigint;
  maxPrice: bigint;
  maxAgeSlots: bigint;
  paused: boolean;
}

export function decodeOraclePolicy(raw: Uint8Array): OraclePolicyState {
  // [0] disc | [1..33] dwallet | [33..65] owner | [65..97] oracle_feed
  // [97..105] min_price (i64) | [105..113] max_price (i64) | [113..121] max_age_slots (u64)
  // [121..129] paused (u64)
  if (raw.length < 129) {
    throw new Error(`OraclePolicy too small: got ${raw.length}, want >= 129`);
  }
  if (raw[0] !== DISC_ORACLE) {
    throw new Error(`OraclePolicy discriminator mismatch: ${raw[0]}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  return {
    dwallet: addrDecoder.decode(raw.subarray(1, 33)) as Address,
    owner: addrDecoder.decode(raw.subarray(33, 65)) as Address,
    oracleFeed: addrDecoder.decode(raw.subarray(65, 97)) as Address,
    minPrice: view.getBigInt64(97, true),
    maxPrice: view.getBigInt64(105, true),
    maxAgeSlots: view.getBigUint64(113, true),
    paused: view.getBigUint64(121, true) !== 0n,
  };
}

// ── PasskeyPolicy ───────────────────────────────────────────────────────

export interface PasskeyPolicyState {
  dwallet: Address;
  owner: Address;
  thresholdAmount: bigint;
  passkeyPubkeyHashHex: string;
  paused: boolean;
}

export function decodePasskeyPolicy(raw: Uint8Array): PasskeyPolicyState {
  // [0] disc | [1..33] dwallet | [33..65] owner | [65..73] threshold_amount (u64)
  // [73..105] passkey_pubkey_hash | [105..113] paused (u64)
  if (raw.length < 113) {
    throw new Error(`PasskeyPolicy too small: got ${raw.length}, want >= 113`);
  }
  if (raw[0] !== DISC_PASSKEY) {
    throw new Error(`PasskeyPolicy discriminator mismatch: ${raw[0]}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const hashBytes = raw.subarray(73, 105);
  return {
    dwallet: addrDecoder.decode(raw.subarray(1, 33)) as Address,
    owner: addrDecoder.decode(raw.subarray(33, 65)) as Address,
    thresholdAmount: view.getBigUint64(65, true),
    passkeyPubkeyHashHex: Array.from(hashBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
    paused: view.getBigUint64(105, true) !== 0n,
  };
}

// ── FHEGatedPolicy ──────────────────────────────────────────────────────

export interface FHEGatedPolicyState {
  dwallet: Address;
  owner: Address;
  fheAuthority: Address;
  decisionMaxAgeSlots: bigint;
  paused: boolean;
}

export function decodeFHEGatedPolicy(raw: Uint8Array): FHEGatedPolicyState {
  // [0] disc | [1..33] dwallet | [33..65] owner | [65..97] fhe_authority
  // [97..105] decision_max_age_slots (u64) | [105..113] paused (u64)
  if (raw.length < 113) {
    throw new Error(`FHEGatedPolicy too small: got ${raw.length}, want >= 113`);
  }
  if (raw[0] !== DISC_FHE_GATED) {
    throw new Error(`FHEGatedPolicy discriminator mismatch: ${raw[0]}`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  return {
    dwallet: addrDecoder.decode(raw.subarray(1, 33)) as Address,
    owner: addrDecoder.decode(raw.subarray(33, 65)) as Address,
    fheAuthority: addrDecoder.decode(raw.subarray(65, 97)) as Address,
    decisionMaxAgeSlots: view.getBigUint64(97, true),
    paused: view.getBigUint64(105, true) !== 0n,
  };
}

// ── Generic dispatch helper ─────────────────────────────────────────────

export type TemplateName =
  | 'time-lock'
  | 'allowlist-destinations'
  | 'velocity-guard'
  | 'session-keys'
  | 'oracle-conditional'
  | 'passkey-step-up'
  | 'fhe-gated';

export type AnyPolicyState =
  | (TimeLockPolicyState & { template: 'time-lock' })
  | (AllowlistPolicyState & { template: 'allowlist-destinations' })
  | (VelocityPolicyState & { template: 'velocity-guard' })
  | (SessionKeyPolicyState & { template: 'session-keys' })
  | (OraclePolicyState & { template: 'oracle-conditional' })
  | (PasskeyPolicyState & { template: 'passkey-step-up' })
  | (FHEGatedPolicyState & { template: 'fhe-gated' });

/**
 * decodePolicyState dispatches to the right decoder based on the template
 * name. Throws when the discriminator/size doesn't match the expected layout.
 *
 * Use it from the recovery layer when you've resolved a policy address back
 * to its template (e.g. via `policy_subscriptions.template`).
 */
export function decodePolicyState(template: TemplateName, raw: Uint8Array): AnyPolicyState {
  switch (template) {
    case 'time-lock':
      return { template, ...decodeTimeLockPolicy(raw) };
    case 'allowlist-destinations':
      return { template, ...decodeAllowlistPolicy(raw) };
    case 'velocity-guard':
      return { template, ...decodeVelocityPolicy(raw) };
    case 'session-keys':
      return { template, ...decodeSessionKeyPolicy(raw) };
    case 'oracle-conditional':
      return { template, ...decodeOraclePolicy(raw) };
    case 'passkey-step-up':
      return { template, ...decodePasskeyPolicy(raw) };
    case 'fhe-gated':
      return { template, ...decodeFHEGatedPolicy(raw) };
  }
}

// silence unused-import warning when only some decoders are imported
export const _toAddress = toAddress;
