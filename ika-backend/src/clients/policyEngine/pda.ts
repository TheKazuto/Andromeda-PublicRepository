import { getProgramDerivedAddress, getAddressEncoder, type Address } from '@solana/kit'
import { createHash } from 'node:crypto'
import {
  MEMBER_SLOT_LEN,
  SEED_CPI_AUTHORITY,
  SEED_ENGINE,
  SEED_EVENT_AUTHORITY,
  SEED_PASSKEY_SESSION,
  SEED_QUORUM_SESSION,
  SEED_SESSION,
  seedForKind,
  type RuleKind,
} from './program.js'

const addrEncoder = getAddressEncoder()

interface PdaResult {
  address: Address
  bump: number
}

const enginePdaCache = new Map<string, PdaResult>()
const rulePdaCache = new Map<string, PdaResult>()
const cpiAuthorityCache = new Map<string, PdaResult>()
const eventAuthorityCache = new Map<string, PdaResult>()
const CACHE_CAP = 4096

function bytesHex(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 1) s += b[i]!.toString(16).padStart(2, '0')
  return s
}

/** Computes `sha256(init_authority_slot)` — the 32-byte digest that
 *  participates in the engine PDA seed (PE-008 / Audit C2). */
export function initAuthorityHashFromSlot(slot: Uint8Array): Uint8Array {
  if (slot.length !== MEMBER_SLOT_LEN) {
    throw new Error(`init_authority_slot must be ${MEMBER_SLOT_LEN} bytes, got ${slot.length}`)
  }
  const h = createHash('sha256')
  h.update(slot)
  return new Uint8Array(h.digest())
}

/** Derives the PolicyEngine PDA.
 *  Seeds: [b"policy_engine", dwallet, init_authority_hash]. */
export async function enginePda(
  programId: Address,
  dwallet: Address,
  initAuthorityHash: Uint8Array,
): Promise<PdaResult> {
  if (initAuthorityHash.length !== 32) {
    throw new Error(`init_authority_hash must be 32 bytes, got ${initAuthorityHash.length}`)
  }
  const key = `${programId}:${dwallet}:${bytesHex(initAuthorityHash)}`
  const cached = enginePdaCache.get(key)
  if (cached) return cached
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_ENGINE, addrEncoder.encode(dwallet), initAuthorityHash],
  })
  const result: PdaResult = { address, bump: Number(bumpRaw) }
  if (enginePdaCache.size >= CACHE_CAP) enginePdaCache.clear()
  enginePdaCache.set(key, result)
  return result
}

/** Derives a sub-PDA for a given rule kind and slot.
 *  Seeds: [b"rule_<kind>", engine_pda, slot_u8]. */
export async function rulePda(
  programId: Address,
  engine: Address,
  kind: RuleKind,
  slotIndex: number,
): Promise<PdaResult> {
  if (slotIndex < 0 || slotIndex > 255) {
    throw new Error(`slotIndex out of u8 range: ${slotIndex}`)
  }
  const key = `${programId}:${engine}:${kind}:${slotIndex}`
  const cached = rulePdaCache.get(key)
  if (cached) return cached
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [seedForKind(kind), addrEncoder.encode(engine), new Uint8Array([slotIndex])],
  })
  const result: PdaResult = { address, bump: Number(bumpRaw) }
  if (rulePdaCache.size >= CACHE_CAP) rulePdaCache.clear()
  rulePdaCache.set(key, result)
  return result
}

/** Derives the CPI authority PDA (target of `transfer_ownership` for any
 *  dWallet whose authority is delegated to the policy-engine). */
export async function cpiAuthorityPda(programId: Address): Promise<PdaResult> {
  const cached = cpiAuthorityCache.get(programId)
  if (cached) return cached
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_CPI_AUTHORITY],
  })
  const result: PdaResult = { address, bump: Number(bumpRaw) }
  cpiAuthorityCache.set(programId, result)
  return result
}

/** Derives an ephemeral Session PDA (F8b).
 *  Seeds: [b"session", engine_pda, session_index_u32_le]. */
export async function sessionPda(
  programId: Address,
  engine: Address,
  sessionIndex: number,
): Promise<PdaResult> {
  if (sessionIndex < 0 || sessionIndex > 0xffff_ffff) {
    throw new Error(`sessionIndex out of u32 range: ${sessionIndex}`)
  }
  const idx = new Uint8Array(4)
  new DataView(idx.buffer).setUint32(0, sessionIndex, true)
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_SESSION, addrEncoder.encode(engine), idx],
  })
  return { address, bump: Number(bumpRaw) }
}

/** Derives the PasskeySession PDA (F9d — passkey-recovery session).
 *  Seeds: [b"passkey_session", engine_pda, passkey_session_nonce_u64_le]. */
export async function passkeySessionPda(
  programId: Address,
  engine: Address,
  passkeySessionNonce: bigint,
): Promise<PdaResult> {
  const nonce = new Uint8Array(8)
  new DataView(nonce.buffer).setBigUint64(0, passkeySessionNonce, true)
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_PASSKEY_SESSION, addrEncoder.encode(engine), nonce],
  })
  return { address, bump: Number(bumpRaw) }
}

/** Derives the QuorumSession PDA (F9b — M-of-N recovery staging).
 *  Seeds: [b"quorum_session", engine_pda, session_nonce_u64_le]. */
export async function quorumSessionPda(
  programId: Address,
  engine: Address,
  sessionNonce: bigint,
): Promise<PdaResult> {
  const nonce = new Uint8Array(8)
  new DataView(nonce.buffer).setBigUint64(0, sessionNonce, true)
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_QUORUM_SESSION, addrEncoder.encode(engine), nonce],
  })
  return { address, bump: Number(bumpRaw) }
}

/** Derives the Quasar event authority PDA. Required as a read-only account
 *  in every instruction that emits events. */
export async function eventAuthorityPda(programId: Address): Promise<PdaResult> {
  const cached = eventAuthorityCache.get(programId)
  if (cached) return cached
  const [address, bumpRaw] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [SEED_EVENT_AUTHORITY],
  })
  const result: PdaResult = { address, bump: Number(bumpRaw) }
  eventAuthorityCache.set(programId, result)
  return result
}
