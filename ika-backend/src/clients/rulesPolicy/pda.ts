import { getProgramDerivedAddress, getAddressEncoder, type Address } from '@solana/kit'
import {
  CPI_AUTHORITY_PDA_SEED,
  EVENT_AUTHORITY_PDA_SEED,
  QUORUM_SESSION_PDA_SEED,
  RULES_POLICY_PDA_SEED,
} from './program.js'

const addrEncoder = getAddressEncoder()

// ── PDA cache ──────────────────────────────────────────────────────
//
// PDAs derive from deterministic seeds — the result is stable for the
// same (programId, seeds). Recomputing via SHA-256 on every request is
// wasted CPU on the Recovery Layer hot path.
//
// CPI/event authority: 1 entry per programId (constant).
// Rules-policy / quorum-session: bounded LRU.

interface PdaResult {
  address: Address
  bump: number
}

const cpiAuthorityCache = new Map<string, PdaResult>()
const eventAuthorityCache = new Map<string, PdaResult>()

const POLICY_PDA_CACHE_CAP = 4096
const policyPdaCache = new Map<string, PdaResult>()

const SESSION_PDA_CACHE_CAP = 4096
const sessionPdaCache = new Map<string, PdaResult>()

function bytesHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 1) {
    s += bytes[i]!.toString(16).padStart(2, '0')
  }
  return s
}

function policyKey(programId: Address, dwallet: Address, initAuthorityHash: Uint8Array): string {
  return `${programId}:${dwallet}:${bytesHex(initAuthorityHash)}`
}

function sessionKey(programId: Address, dwallet: Address, sessionNonce: bigint): string {
  return `${programId}:${dwallet}:${sessionNonce.toString()}`
}

/**
 * Audit C2 (Opção 4) helper: SHA-256 of the 34-byte init_authority slot.
 * Returns the 32-byte hash that participates in the policy PDA seed.
 *
 * Uses Node's `crypto.createHash` (sync, no Buffer/SharedArrayBuffer
 * narrowness issues) to mirror the on-chain `sha256` implementation.
 */
export async function initAuthorityHashFromSlot(slot: Uint8Array): Promise<Uint8Array> {
  if (slot.length !== 34) {
    throw new Error(`init_authority_slot must be 34 bytes, got ${slot.length}`)
  }
  const { createHash } = await import('node:crypto')
  const h = createHash('sha256')
  h.update(slot)
  return new Uint8Array(h.digest())
}

function lruSet<K, V>(map: Map<K, V>, cap: number, key: K, value: V): void {
  if (map.has(key)) map.delete(key)
  map.set(key, value)
  if (map.size > cap) {
    const oldest = map.keys().next().value
    if (oldest !== undefined) map.delete(oldest)
  }
}

function lruGet<K, V>(map: Map<K, V>, key: K): V | undefined {
  const v = map.get(key)
  if (v !== undefined) {
    map.delete(key)
    map.set(key, v)
  }
  return v
}

/**
 * PDA: rules_policy account.
 *
 * Audit C2 (Opção 4): seeds = [b"rules_policy", dwallet, init_authority_hash].
 * Each (dwallet, init_authority) pair maps to a distinct PDA — squat-resistant.
 */
export async function findRulesPolicyPda(
  programId: Address,
  dwallet: Address,
  initAuthorityHash: Uint8Array,
): Promise<PdaResult> {
  if (initAuthorityHash.length !== 32) {
    throw new Error(`init_authority_hash must be 32 bytes, got ${initAuthorityHash.length}`)
  }
  const key = policyKey(programId, dwallet, initAuthorityHash)
  const cached = lruGet(policyPdaCache, key)
  if (cached) return cached
  const dwalletBytes = addrEncoder.encode(dwallet)
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [RULES_POLICY_PDA_SEED, dwalletBytes, initAuthorityHash],
  })
  const result: PdaResult = { address, bump }
  lruSet(policyPdaCache, POLICY_PDA_CACHE_CAP, key, result)
  return result
}

/**
 * PDA: quorum_session account. seeds = [b"quorum_session", dwallet, session_nonce_le]
 *
 * `sessionNonce` is serialized as 8-byte little-endian (`u64.to_le_bytes()`
 * in the contract).
 */
export async function findQuorumSessionPda(
  programId: Address,
  dwallet: Address,
  sessionNonce: bigint,
): Promise<PdaResult> {
  const key = sessionKey(programId, dwallet, sessionNonce)
  const cached = lruGet(sessionPdaCache, key)
  if (cached) return cached
  const dwalletBytes = addrEncoder.encode(dwallet)
  const nonceBytes = new Uint8Array(8)
  new DataView(nonceBytes.buffer).setBigUint64(0, sessionNonce, true)
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [QUORUM_SESSION_PDA_SEED, dwalletBytes, nonceBytes],
  })
  const result: PdaResult = { address, bump }
  lruSet(sessionPdaCache, SESSION_PDA_CACHE_CAP, key, result)
  return result
}

/**
 * PDA: cpi_authority account. seeds = [b"__ika_cpi_authority"]
 */
export async function findCpiAuthorityPda(programId: Address): Promise<PdaResult> {
  const cached = cpiAuthorityCache.get(programId)
  if (cached) return cached
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [CPI_AUTHORITY_PDA_SEED],
  })
  const result: PdaResult = { address, bump }
  cpiAuthorityCache.set(programId, result)
  return result
}

/**
 * PDA: event_authority used by `emit_cpi!`. seeds = [b"__event_authority"]
 */
export async function findEventAuthorityPda(programId: Address): Promise<PdaResult> {
  const cached = eventAuthorityCache.get(programId)
  if (cached) return cached
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [EVENT_AUTHORITY_PDA_SEED],
  })
  const result: PdaResult = { address, bump }
  eventAuthorityCache.set(programId, result)
  return result
}

const MESSAGE_APPROVAL_SEED = new TextEncoder().encode('message_approval')

/**
 * MessageApproval PDA on the Ika dWallet program.
 * seeds = [b"message_approval", dwallet, message_digest]
 */
export async function findMessageApprovalPda(
  ikaProgramId: Address,
  dwallet: Address,
  messageDigest: Uint8Array,
): Promise<PdaResult> {
  if (messageDigest.length !== 32) {
    throw new Error('message_digest must be 32 bytes')
  }
  const dwalletBytes = addrEncoder.encode(dwallet)
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: ikaProgramId,
    seeds: [MESSAGE_APPROVAL_SEED, dwalletBytes, messageDigest],
  })
  return { address, bump }
}

export function _resetPdaCaches(): void {
  cpiAuthorityCache.clear()
  eventAuthorityCache.clear()
  policyPdaCache.clear()
  sessionPdaCache.clear()
}
