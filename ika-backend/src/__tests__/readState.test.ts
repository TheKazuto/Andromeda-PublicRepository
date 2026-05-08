// Unit tests for the policy state decoders. The TimeLockPolicy fixture is
// the actual hex bytes returned by `solana account` for the policy created
// by scripts/test_lifecycle.go in our prior runtime validation — known-good
// reference data.

import { describe, it, expect } from 'vitest';
import {
  decodeAllowlistPolicy,
  decodeFHEGatedPolicy,
  decodeOraclePolicy,
  decodePasskeyPolicy,
  decodePolicyState,
  decodeSessionKeyPolicy,
  decodeTimeLockPolicy,
  decodeVelocityPolicy,
} from '../clients/policies/readState.js';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function u64LEHex(v: bigint): string {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, v, true);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function i64LEHex(v: bigint): string {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigInt64(0, v, true);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function u32LEHex(v: number): string {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, v, true);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const ZEROS_32 = '00'.repeat(32);
const ONES_32 = '11'.repeat(32);
const TWOS_32 = '22'.repeat(32);
const THREES_32 = '33'.repeat(32);

describe('decodeTimeLockPolicy', () => {
  // Reference fixture: live devnet bytes from policy
  // AN51uMJvDe7XD6X85yjcCZrxyuMnNQcpWNVfzwad74y9 (created by test_lifecycle.go).
  const liveHex =
    '01' +
    '34cc9a31f3e4364be69fa2d28d600df211bbcaefbf353cd677497592b84816e5' + // dwallet
    '90f7ce7d5b458f1ba9d4ed794a8ca93814d548d19ea3e0400273e53c8599387f' + // owner
    '6400000000000000' + // start_slot = 100
    '00c2eb0b00000000' + // end_slot = 200_000_000
    '0000000000000000' + // recurring_period_slots = 0
    '0000000000000000' + // mode = 0 (absolute)
    '0000000000000000'; // paused = 0 (active)

  it('decodes the canonical layout from devnet bytes', () => {
    const out = decodeTimeLockPolicy(hexToBytes(liveHex));
    expect(out.startSlot).toBe(100n);
    expect(out.endSlot).toBe(200_000_000n);
    expect(out.recurringPeriodSlots).toBe(0n);
    expect(out.mode).toBe('absolute');
    expect(out.paused).toBe(false);
  });

  it('reports paused=true when paused field is non-zero', () => {
    const paused =
      '01' + ONES_32 + TWOS_32 + u64LEHex(0n) + u64LEHex(100n) +
      u64LEHex(0n) + u64LEHex(0n) + u64LEHex(1n);
    const out = decodeTimeLockPolicy(hexToBytes(paused));
    expect(out.paused).toBe(true);
  });

  it('rejects wrong discriminator', () => {
    const bad = '02' + ONES_32 + TWOS_32 + u64LEHex(0n).repeat(5);
    expect(() => decodeTimeLockPolicy(hexToBytes(bad))).toThrow(/discriminator/);
  });

  it('rejects truncated payload', () => {
    const short = '01' + ONES_32;
    expect(() => decodeTimeLockPolicy(hexToBytes(short))).toThrow(/too small/);
  });
});

describe('decodeAllowlistPolicy', () => {
  it('reads count + dense destinations slice', () => {
    const flat = ZEROS_32.repeat(32); // 1024 bytes of zeros for 32 destination slots
    // overwrite the first 2 slots with ONES_32 + TWOS_32
    const flatBytes = hexToBytes(flat);
    flatBytes.set(hexToBytes(ONES_32), 0);
    flatBytes.set(hexToBytes(TWOS_32), 32);
    const flatHex = [...flatBytes].map((b) => b.toString(16).padStart(2, '0')).join('');

    const hex =
      '01' + ONES_32 + TWOS_32 + '00' /* paused */ + '02' /* count */ + flatHex;
    const out = decodeAllowlistPolicy(hexToBytes(hex));
    expect(out.destinations.length).toBe(2);
    expect(out.paused).toBe(false);
  });
});

describe('decodeVelocityPolicy', () => {
  it('reads u32/u64 fields little-endian', () => {
    const hex =
      '01' +
      ONES_32 + TWOS_32 +
      '00' /* paused */ +
      u32LEHex(100) +
      u64LEHex(216_000n) +
      u32LEHex(7) +
      u64LEHex(123_456n);
    const out = decodeVelocityPolicy(hexToBytes(hex));
    expect(out.maxSigsPerWindow).toBe(100);
    expect(out.windowSlots).toBe(216_000n);
    expect(out.currentCount).toBe(7);
    expect(out.windowStartSlot).toBe(123_456n);
  });
});

describe('decodeSessionKeyPolicy', () => {
  it('reads count-prefixed allowed_programs slice', () => {
    const flat = ZEROS_32.repeat(8); // 256 bytes
    const flatBytes = hexToBytes(flat);
    flatBytes.set(hexToBytes(THREES_32), 0);
    const flatHex = [...flatBytes].map((b) => b.toString(16).padStart(2, '0')).join('');

    const hex =
      '01' +
      ONES_32 +
      TWOS_32 +
      THREES_32 + // session_key
      u64LEHex(1_000_000n) +
      u64LEHex(500_000n) +
      u32LEHex(3) +
      u32LEHex(100) +
      '01' + // allowed_program_count
      flatHex;
    const out = decodeSessionKeyPolicy(hexToBytes(hex));
    expect(out.maxAmountPerTx).toBe(500_000n);
    expect(out.usedCount).toBe(3);
    expect(out.maxUses).toBe(100);
    expect(out.allowedPrograms.length).toBe(1);
  });
});

describe('decodeOraclePolicy', () => {
  it('handles negative min_price (i64)', () => {
    const hex =
      '01' +
      ONES_32 + TWOS_32 + THREES_32 +
      i64LEHex(-1000n) +
      i64LEHex(1_000_000n) +
      u64LEHex(25n) +
      u64LEHex(0n);
    const out = decodeOraclePolicy(hexToBytes(hex));
    expect(out.minPrice).toBe(-1000n);
    expect(out.maxPrice).toBe(1_000_000n);
    expect(out.maxAgeSlots).toBe(25n);
    expect(out.paused).toBe(false);
  });
});

describe('decodePasskeyPolicy', () => {
  it('returns hash as hex string', () => {
    const hex =
      '01' +
      ONES_32 + TWOS_32 +
      u64LEHex(5_000n) +
      'aa'.repeat(32) +
      u64LEHex(0n);
    const out = decodePasskeyPolicy(hexToBytes(hex));
    expect(out.thresholdAmount).toBe(5_000n);
    expect(out.passkeyPubkeyHashHex).toBe('aa'.repeat(32));
  });
});

describe('decodeFHEGatedPolicy', () => {
  it('reads fhe_authority + max_age', () => {
    const hex =
      '01' +
      ONES_32 + TWOS_32 + THREES_32 +
      u64LEHex(10n) +
      u64LEHex(1n);
    const out = decodeFHEGatedPolicy(hexToBytes(hex));
    expect(out.decisionMaxAgeSlots).toBe(10n);
    expect(out.paused).toBe(true);
  });
});

describe('decodePolicyState', () => {
  it('dispatches to the right decoder by template name', () => {
    const tlHex =
      '01' + ONES_32 + TWOS_32 + u64LEHex(0n) + u64LEHex(100n) +
      u64LEHex(0n) + u64LEHex(0n) + u64LEHex(0n);
    const out = decodePolicyState('time-lock', hexToBytes(tlHex));
    expect(out.template).toBe('time-lock');
    if (out.template !== 'time-lock') return;
    expect(out.endSlot).toBe(100n);
  });
});
