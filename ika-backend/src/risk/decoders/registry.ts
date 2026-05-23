// Pluggable per-chain-family transaction decoder registry.
//
// EVM and Solana stay inline in `../decode.ts` (battle-tested, many callers).
// Every other family plugs in here: `decodeForChain` looks the family up by
// `chainFamily` and falls back to the honest "cannot verify" path when none is
// registered. This keeps the advisory risk layer extensible without touching
// the EVM/Solana hot paths.

import type { CalldataRisk } from '../types.js'

/** Context passed to a decoder — lets it resolve network-specific details. */
export interface DecodeContext {
  /** Full CAIP-2 chain id (e.g. "bip122:000000000019d6...", "cosmos:cosmoshub-4"). */
  chainId: string
  /** CAIP-2 namespace (e.g. "bip122", "cosmos"). */
  namespace: string
  /** CAIP-2 reference (chain / genesis id). */
  reference: string
}

export interface ChainDecoder {
  /** chainFamily handled — matches `chains.ts` `chainFamily`. */
  readonly family: string
  /**
   * Decode a transaction/message payload (hex) into a calldata-risk view. MUST
   * NOT throw — on any failure return `effectsExtracted: false` with a clear
   * reason so the caller degrades honestly instead of crashing.
   */
  decode(payloadHex: string, kind: 'transaction' | 'message', ctx: DecodeContext): CalldataRisk
}

/** Decode a hex payload (with or without 0x) into bytes. */
export function hexToBytes(payloadHex: string): Uint8Array {
  const norm = payloadHex.startsWith('0x') ? payloadHex.slice(2) : payloadHex
  return Uint8Array.from(Buffer.from(norm, 'hex'))
}

/** Honest "decoded nothing" result — the destination cannot be verified. */
export function unverifiable(reason: string): CalldataRisk {
  return { level: 'critical', reasons: [reason], effectsExtracted: false }
}

/** A signed-message (not a transaction) — low risk, nothing to simulate. */
export function messageSignature(): CalldataRisk {
  return { level: 'none', reasons: ['message signature (not a transaction)'], effectsExtracted: true }
}

const LEVEL_RANK: Record<CalldataRisk['level'], number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** Returns the higher-severity of two levels. */
export function maxLevel(a: CalldataRisk['level'], b: CalldataRisk['level']): CalldataRisk['level'] {
  return LEVEL_RANK[b] > LEVEL_RANK[a] ? b : a
}
