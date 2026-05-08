/**
 * Builders for Solana's three signature-verification precompile instructions.
 *
 * Each precompile call carries `(signature, public_key_or_eth_address, message)`
 * inline in its instruction data, with offsets pointing within the same
 * instruction (self-contained — sentinel `0xFFFF` for the long layouts,
 * `0xFF` for the short Secp256k1 layout). The Solana runtime verifies the
 * signature natively before the next instruction in the transaction runs;
 * the main on-chain program then reads the precompile invocation back from
 * the Instructions sysvar and trusts the validation.
 *
 * Layouts:
 *
 *   Ed25519 / Secp256r1 (long, 14-byte offsets, u16 ix-index):
 *     [0]                       num_records (u8)
 *     [1]                       padding (u8)
 *     [2..2+14*R]               offsets records
 *     [..]                      signatures + pubkeys + messages
 *
 *   Secp256k1 (short, 11-byte offsets, u8 ix-index):
 *     [0]                       num_records (u8)
 *     [1..1+11*R]               offsets records
 *     [..]                      signatures (65 = 64 sig + 1 recid) + eth_addresses (20) + messages
 *
 *  See: https://solana.com/docs/core/programs/precompiles
 */

import { AccountRole, type Address, type Instruction } from '@solana/kit'

export const ED25519_PROGRAM_ADDRESS = 'Ed25519SigVerify111111111111111111111111111' as Address
export const SECP256K1_PROGRAM_ADDRESS = 'KeccakSecp256k11111111111111111111111111111' as Address
export const SECP256R1_PROGRAM_ADDRESS = 'Secp256r1SigVerify1111111111111111111111111' as Address

const ED25519_PUBKEY_LEN = 32
const SECP256K1_ETH_ADDR_LEN = 20
const SECP256R1_PUBKEY_LEN = 33
const ED25519_SIG_LEN = 64
const SECP256R1_SIG_LEN = 64
const SECP256K1_SIG_WITH_RECID_LEN = 65

const LONG_OFFSETS_LEN = 14
const SHORT_OFFSETS_LEN = 11
const LONG_SELF_INDEX = 0xffff
const SHORT_SELF_INDEX = 0xff

function emptyAccounts(): { address: Address; role: AccountRole }[] {
  return []
}

function asAccountMetas(metas: { address: Address; role: AccountRole }[]) {
  return metas.map((a) => ({ address: a.address, role: a.role }))
}

// ── Ed25519 ────────────────────────────────────────────────────

export function buildEd25519PrecompileInstruction(input: {
  publicKey: Uint8Array // 32 bytes
  message: Uint8Array
  signature: Uint8Array // 64 bytes
}): Instruction {
  if (input.publicKey.length !== ED25519_PUBKEY_LEN) {
    throw new Error(`Ed25519 pubkey must be ${ED25519_PUBKEY_LEN} bytes`)
  }
  if (input.signature.length !== ED25519_SIG_LEN) {
    throw new Error(`Ed25519 signature must be ${ED25519_SIG_LEN} bytes`)
  }

  const headerLen = 2
  const offsetsLen = LONG_OFFSETS_LEN
  const sigOffset = headerLen + offsetsLen
  const pubkeyOffset = sigOffset + ED25519_SIG_LEN
  const messageOffset = pubkeyOffset + ED25519_PUBKEY_LEN
  const totalLen = messageOffset + input.message.length

  const data = new Uint8Array(totalLen)
  const dv = new DataView(data.buffer)
  // header
  data[0] = 1 // num_records
  data[1] = 0 // padding
  // offsets record (14 bytes)
  let off = headerLen
  dv.setUint16(off, sigOffset, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  dv.setUint16(off, pubkeyOffset, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  dv.setUint16(off, messageOffset, true); off += 2
  dv.setUint16(off, input.message.length, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  // payload
  data.set(input.signature, sigOffset)
  data.set(input.publicKey, pubkeyOffset)
  data.set(input.message, messageOffset)

  return {
    programAddress: ED25519_PROGRAM_ADDRESS,
    accounts: asAccountMetas(emptyAccounts()),
    data,
  }
}

// ── Secp256k1 ──────────────────────────────────────────────────

export function buildSecp256k1PrecompileInstruction(input: {
  ethAddress: Uint8Array // 20 bytes (keccak256(uncompressed_pubkey)[12..])
  message: Uint8Array
  signature: Uint8Array // 65 bytes (r || s || recovery_id)
}): Instruction {
  if (input.ethAddress.length !== SECP256K1_ETH_ADDR_LEN) {
    throw new Error(`Secp256k1 eth_address must be ${SECP256K1_ETH_ADDR_LEN} bytes`)
  }
  if (input.signature.length !== SECP256K1_SIG_WITH_RECID_LEN) {
    throw new Error(`Secp256k1 signature must be ${SECP256K1_SIG_WITH_RECID_LEN} bytes (r||s||recid)`)
  }

  const headerLen = 1
  const offsetsLen = SHORT_OFFSETS_LEN
  const sigOffset = headerLen + offsetsLen
  const ethAddrOffset = sigOffset + SECP256K1_SIG_WITH_RECID_LEN
  const messageOffset = ethAddrOffset + SECP256K1_ETH_ADDR_LEN
  const totalLen = messageOffset + input.message.length

  const data = new Uint8Array(totalLen)
  const dv = new DataView(data.buffer)
  data[0] = 1 // num_records
  let off = headerLen
  dv.setUint16(off, sigOffset, true); off += 2
  data[off] = SHORT_SELF_INDEX; off += 1
  dv.setUint16(off, ethAddrOffset, true); off += 2
  data[off] = SHORT_SELF_INDEX; off += 1
  dv.setUint16(off, messageOffset, true); off += 2
  dv.setUint16(off, input.message.length, true); off += 2
  data[off] = SHORT_SELF_INDEX; off += 1
  // payload
  data.set(input.signature, sigOffset)
  data.set(input.ethAddress, ethAddrOffset)
  data.set(input.message, messageOffset)

  return {
    programAddress: SECP256K1_PROGRAM_ADDRESS,
    accounts: asAccountMetas(emptyAccounts()),
    data,
  }
}

// ── Secp256r1 ──────────────────────────────────────────────────

export function buildSecp256r1PrecompileInstruction(input: {
  publicKey: Uint8Array // 33 bytes compressed (0x02/0x03 prefix + 32 X)
  message: Uint8Array
  signature: Uint8Array // 64 bytes (r || s, low-S enforced)
}): Instruction {
  if (input.publicKey.length !== SECP256R1_PUBKEY_LEN) {
    throw new Error(`Secp256r1 pubkey must be ${SECP256R1_PUBKEY_LEN} bytes (compressed)`)
  }
  if (input.signature.length !== SECP256R1_SIG_LEN) {
    throw new Error(`Secp256r1 signature must be ${SECP256R1_SIG_LEN} bytes (r||s)`)
  }

  const headerLen = 2
  const offsetsLen = LONG_OFFSETS_LEN
  const sigOffset = headerLen + offsetsLen
  const pubkeyOffset = sigOffset + SECP256R1_SIG_LEN
  const messageOffset = pubkeyOffset + SECP256R1_PUBKEY_LEN
  const totalLen = messageOffset + input.message.length

  const data = new Uint8Array(totalLen)
  const dv = new DataView(data.buffer)
  data[0] = 1
  data[1] = 0
  let off = headerLen
  dv.setUint16(off, sigOffset, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  dv.setUint16(off, pubkeyOffset, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  dv.setUint16(off, messageOffset, true); off += 2
  dv.setUint16(off, input.message.length, true); off += 2
  dv.setUint16(off, LONG_SELF_INDEX, true); off += 2
  data.set(input.signature, sigOffset)
  data.set(input.publicKey, pubkeyOffset)
  data.set(input.message, messageOffset)

  return {
    programAddress: SECP256R1_PROGRAM_ADDRESS,
    accounts: asAccountMetas(emptyAccounts()),
    data,
  }
}
