// Derive chain-native addresses from a dWallet's curve-specific public key.
//
// Ported and adapted from `odws/src/chain/address.ts`
// (https://github.com/Iamknownasfesal/odws). Differences from the original:
//   - Keyed off our `CurveName` (not the Sui-side `@ika.xyz/sdk` `Curve` enum).
//   - Uses the libraries already vendored in this service (`bs58`, `bech32`,
//     `@noble/*`) instead of hand-rolled base58/bech32 (less drift risk).
//   - Cosmos uses plain bech32 (NO segwit witness-version byte) — the odws
//     original prepends a `0` witness version for cosmos too, which is wrong for
//     non-segwit bech32 accounts. Bitcoin P2WPKH keeps the witness-version `0`.
//   - Unknown namespaces throw instead of falling back to a hex blob.
//
// CRITICAL (plan §1.3): the input MUST be the dWallet's `dwalletPublicKey`
// (the DKG-produced, curve-specific key), NOT the Ed25519 `signerPubkey`. For a
// Secp256k1 dWallet the signer key is still 32-byte Ed25519 and would derive
// garbage EVM/BTC addresses.
//
// All functions are read-only and never touch private material.

import bs58 from 'bs58'
import { bech32 } from 'bech32'
import { base32nopad } from '@scure/base'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256, sha512_256 } from '@noble/hashes/sha2.js'
import { keccak_256, sha3_256 } from '@noble/hashes/sha3.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { type CurveName } from '../engine/ika-client/bcs.js'
import { parseChainId } from './chains.js'
import { InvalidPublicKeyError, UnsupportedChainError } from './errors.js'

/** Bitcoin mainnet genesis-block hash — the CAIP-2 `bip122` mainnet reference. */
const BTC_MAINNET_REF = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

/** CAIP-2 references used by `deriveAccountsForCurve` (mainnets). For the
 *  network-independent address formats the reference is cosmetic. */
const SOLANA_MAINNET_REF = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
const COSMOS_HUB_REF = 'cosmoshub-4'
const TRON_MAINNET_REF = '0x2b6653dc'
const ALGORAND_MAINNET_REF = 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73k'
const APTOS_MAINNET_REF = '1'
const MVX_MAINNET_REF = '1'

const ADDRESS_NAMESPACES: readonly string[] = [
  'eip155', 'tron', 'bip122', 'solana', 'sui', 'cosmos',
  'fil', 'stellar', 'algorand', 'aptos', 'mvx', 'ton', 'vechain',
  'avalanche', 'casper', 'tezos', 'iota',
]

/** Stellar StrKey version byte for an ed25519 public key (the "G" prefix). */
const STELLAR_VERSION_ED25519 = 6 << 3

/** CRC16/XMODEM (poly 0x1021, init 0) — Stellar StrKey checksum. */
function crc16xmodem(data: Uint8Array): number {
  let crc = 0
  for (const b of data) {
    crc ^= b << 8
    for (let i = 0; i < 8; i += 1) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff
    }
  }
  return crc
}

function toHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 1) s += bytes[i]!.toString(16).padStart(2, '0')
  return s
}

/** Decompress/normalize a secp256k1 key to the 65-byte uncompressed form. */
function secpUncompressed(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new InvalidPublicKeyError(`secp256k1 public key must be 33 or 65 bytes, got ${publicKey.length}`)
  }
  return secp256k1.Point.fromBytes(publicKey).toBytes(false)
}

/** Compress/normalize a secp256k1 key to the 33-byte compressed form. */
function secpCompressed(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new InvalidPublicKeyError(`secp256k1 public key must be 33 or 65 bytes, got ${publicKey.length}`)
  }
  return secp256k1.Point.fromBytes(publicKey).toBytes(true)
}

function assertEd25519(publicKey: Uint8Array): void {
  if (publicKey.length !== 32) {
    throw new InvalidPublicKeyError(`ed25519 public key must be 32 bytes, got ${publicKey.length}`)
  }
}

/** secp256k1 → HASH160 (RIPEMD160(SHA256(compressed))), used by Cosmos & Bitcoin. */
function hash160(compressed: Uint8Array): Uint8Array {
  return ripemd160(sha256(compressed))
}

/** Bitcoin legacy P2PKH (base58check). version 0x00 mainnet / 0x6f testnet. */
function bitcoinP2pkh(publicKey: Uint8Array, mainnet = true): string {
  const payload = new Uint8Array(1 + 20)
  payload[0] = mainnet ? 0x00 : 0x6f
  payload.set(hash160(secpCompressed(publicKey)), 1)
  const checksum = sha256(sha256(payload)).slice(0, 4)
  const full = new Uint8Array(payload.length + 4)
  full.set(payload, 0)
  full.set(checksum, payload.length)
  return bs58.encode(full)
}

/** EIP-55 mixed-case checksum for a 40-char lowercase hex address (no 0x). */
function eip55Checksum(lowerHex: string): string {
  const hash = toHex(keccak_256(new TextEncoder().encode(lowerHex)))
  let out = ''
  for (let i = 0; i < lowerHex.length; i += 1) {
    out += parseInt(hash[i]!, 16) >= 8 ? lowerHex[i]!.toUpperCase() : lowerHex[i]
  }
  return out
}

/** EVM 20-byte address bytes from a secp256k1 key (keccak256(uncompressed[1:])[12:]). */
function evmAddressBytes(publicKey: Uint8Array): Uint8Array {
  const uncompressed = secpUncompressed(publicKey)
  return keccak_256(uncompressed.slice(1)).slice(12)
}

/**
 * Derive the chain-native address for `chainId` from `publicKey` (the dWallet's
 * curve-specific public key — see file header).
 *
 * @throws {ChainIdParseError} / {UnsupportedChainError} / {InvalidPublicKeyError}
 */
export function deriveAddress(publicKey: Uint8Array, chainId: string): string {
  const { namespace, reference } = parseChainId(chainId)

  switch (namespace) {
    case 'eip155': {
      return '0x' + eip55Checksum(toHex(evmAddressBytes(publicKey)))
    }
    case 'vechain': {
      // Same 20-byte address as EVM, but VeChain canonicalizes lowercase.
      return '0x' + toHex(evmAddressBytes(publicKey))
    }
    case 'tron': {
      // 0x41 prefix + 20-byte address, base58check (double-sha256 checksum).
      const withPrefix = new Uint8Array(21)
      withPrefix[0] = 0x41
      withPrefix.set(evmAddressBytes(publicKey), 1)
      const checksum = sha256(sha256(withPrefix)).slice(0, 4)
      const full = new Uint8Array(25)
      full.set(withPrefix, 0)
      full.set(checksum, 21)
      return bs58.encode(full)
    }
    case 'cosmos': {
      // bech32 of HASH160 — NO segwit witness-version byte.
      const words = bech32.toWords(hash160(secpCompressed(publicKey)))
      return bech32.encode('cosmos', words)
    }
    case 'bip122': {
      // P2WPKH: segwit v0 program = HASH160; bech32 with witness version 0.
      const hrp = reference === BTC_MAINNET_REF ? 'bc' : 'tb'
      const program = bech32.toWords(hash160(secpCompressed(publicKey)))
      return bech32.encode(hrp, [0, ...program])
    }
    case 'solana': {
      assertEd25519(publicKey)
      return bs58.encode(publicKey)
    }
    case 'sui': {
      assertEd25519(publicKey)
      const flagged = new Uint8Array(1 + publicKey.length)
      flagged[0] = 0x00 // Ed25519 flag
      flagged.set(publicKey, 1)
      return '0x' + toHex(blake2b(flagged, { dkLen: 32 }))
    }
    case 'stellar': {
      // StrKey: base32(version || pubkey || crc16xmodem-LE). 35 bytes → 56 chars, no pad.
      assertEd25519(publicKey)
      const payload = new Uint8Array(1 + publicKey.length)
      payload[0] = STELLAR_VERSION_ED25519
      payload.set(publicKey, 1)
      const crc = crc16xmodem(payload)
      const out = new Uint8Array(payload.length + 2)
      out.set(payload, 0)
      out[payload.length] = crc & 0xff
      out[payload.length + 1] = (crc >> 8) & 0xff
      return base32nopad.encode(out)
    }
    case 'algorand': {
      // base32(pubkey || sha512/256(pubkey)[28:32]), no padding.
      assertEd25519(publicKey)
      const cs = sha512_256(publicKey).slice(28)
      const out = new Uint8Array(publicKey.length + 4)
      out.set(publicKey, 0)
      out.set(cs, publicKey.length)
      return base32nopad.encode(out)
    }
    case 'aptos': {
      // Authentication key = sha3-256(pubkey || 0x00 single-ed25519 scheme).
      assertEd25519(publicKey)
      const b = new Uint8Array(publicKey.length + 1)
      b.set(publicKey, 0)
      b[publicKey.length] = 0x00
      return '0x' + toHex(sha3_256(b))
    }
    case 'mvx': {
      // MultiversX: bech32 ("erd") of the raw ed25519 public key.
      assertEd25519(publicKey)
      return bech32.encode('erd', bech32.toWords(publicKey), Infinity)
    }
    case 'ton': {
      // Wallet v5r1 address (non-bounceable, workchain 0). Matches @ton/ton.
      assertEd25519(publicKey)
      return tonWalletV5R1Address(publicKey)
    }
    case 'fil': {
      // f1 (secp256k1): blake2b-160(uncompressed) + blake2b-32 checksum over
      // (protocol||payload), base32 lower-case, "f1" prefix.
      const payload = blake2b(secpUncompressed(publicKey), { dkLen: 20 })
      const checkInput = new Uint8Array(1 + payload.length)
      checkInput[0] = 1 // secp256k1 protocol
      checkInput.set(payload, 1)
      const checksum = blake2b(checkInput, { dkLen: 4 })
      const addrBytes = new Uint8Array(payload.length + checksum.length)
      addrBytes.set(payload, 0)
      addrBytes.set(checksum, payload.length)
      return 'f1' + base32nopad.encode(addrBytes).toLowerCase()
    }
    case 'avalanche': {
      // X-chain: "X-" + bech32("avax", HASH160). (C-chain is eip155.)
      return 'X-' + bech32.encode('avax', bech32.toWords(hash160(secpCompressed(publicKey))), Infinity)
    }
    case 'casper': {
      // account-hash-<hex>, hex = blake2b-256("ed25519" || 0x00 || pubkey).
      assertEd25519(publicKey)
      const tag = new TextEncoder().encode('ed25519')
      const b = new Uint8Array(tag.length + 1 + publicKey.length)
      b.set(tag, 0)
      b[tag.length] = 0x00
      b.set(publicKey, tag.length + 1)
      return 'account-hash-' + toHex(blake2b(b, { dkLen: 32 }))
    }
    case 'tezos': {
      // tz1: base58check(prefix [6,161,159] || blake2b-160(pubkey)).
      assertEd25519(publicKey)
      const prefix = Uint8Array.from([6, 161, 159])
      const h = blake2b(publicKey, { dkLen: 20 })
      const payload = new Uint8Array(prefix.length + h.length)
      payload.set(prefix, 0)
      payload.set(h, prefix.length)
      const checksum = sha256(sha256(payload)).slice(0, 4)
      const full = new Uint8Array(payload.length + 4)
      full.set(payload, 0)
      full.set(checksum, payload.length)
      return bs58.encode(full)
    }
    case 'iota': {
      // IOTA Rebased: 0x + blake2b-256(pubkey). (No flag byte, unlike Sui.)
      assertEd25519(publicKey)
      return '0x' + toHex(blake2b(publicKey, { dkLen: 32 }))
    }
    default:
      throw new UnsupportedChainError(chainId, ADDRESS_NAMESPACES)
  }
}

export interface DerivedAccount {
  chainId: string
  address: string
  /**
   * Script/address type, set only when a chain exposes more than one address
   * format off the same key. Bitcoin returns `p2wpkh` (segwit, default) and
   * `p2pkh` (legacy). Omitted for single-format chains.
   */
  type?: string
}

/**
 * Derive every address a dWallet of `curve` can hold. A Secp256k1 dWallet has
 * EVM / Bitcoin / Cosmos / Tron addresses; a Curve25519 (ed25519) dWallet has
 * Solana / Sui. `publicKey` is the dWallet's curve-specific key.
 */
export function deriveAccountsForCurve(publicKey: Uint8Array, curve: CurveName): DerivedAccount[] {
  let chainIds: string[]
  if (curve === 'Secp256k1') {
    chainIds = [
      'eip155:1',
      `bip122:${BTC_MAINNET_REF}`,
      `cosmos:${COSMOS_HUB_REF}`,
      `tron:${TRON_MAINNET_REF}`,
      'fil:f',
      'vechain:0x4a1208',
      'avalanche:mainnet',
    ]
  } else if (curve === 'Curve25519') {
    chainIds = [
      `solana:${SOLANA_MAINNET_REF}`,
      'sui:mainnet',
      'stellar:pubnet',
      `algorand:${ALGORAND_MAINNET_REF}`,
      `aptos:${APTOS_MAINNET_REF}`,
      `mvx:${MVX_MAINNET_REF}`,
      'ton:mainnet',
      'casper:casper',
      'tezos:mainnet',
      'iota:iota',
    ]
  } else {
    // Secp256r1 / Ristretto: no address-derivable destination chains in B1.
    chainIds = []
  }
  return chainIds.flatMap((chainId): DerivedAccount[] => {
    // Bitcoin exposes two formats off one key: segwit P2WPKH (default) + legacy P2PKH.
    if (chainId.startsWith('bip122:')) {
      return [
        { chainId, address: deriveAddress(publicKey, chainId), type: 'p2wpkh' },
        { chainId, address: bitcoinP2pkh(publicKey, true), type: 'p2pkh' },
      ]
    }
    return [{ chainId, address: deriveAddress(publicKey, chainId) }]
  })
}

// ── TON wallet v5r1 ─────────────────────────────────────────────────────────
// Ported from odws and verified byte-identical against @ton/ton's
// WalletContractV5R1 (StateInit hash + non-bounceable address). Non-bounceable,
// workchain 0, default walletId.

const TON_V5R1_CODE_HASH = new Uint8Array([
  0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4,
  0x57, 0xb8, 0x4e, 0x74, 0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
  0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
])
const TON_V5R1_CODE_DEPTH = 6
const TON_DEFAULT_WALLET_ID = 0x7fffff11

function tonWalletV5R1Address(publicKey: Uint8Array): string {
  const dataHash = tonDataCellHash(publicKey)
  const stateHash = tonStateInitHash(TON_V5R1_CODE_HASH, TON_V5R1_CODE_DEPTH, dataHash)
  return tonEncodeAddress(0, stateHash, false)
}

/** Data cell hash for the wallet v5r1 initial state (322 data bits, 0 refs). */
function tonDataCellHash(publicKey: Uint8Array): Uint8Array {
  const bits: number[] = []
  bits.push(1) // is_signature_allowed
  for (let i = 0; i < 32; i += 1) bits.push(0) // seqno = 0
  for (let shift = 31; shift >= 0; shift -= 1) bits.push((TON_DEFAULT_WALLET_ID >>> shift) & 1)
  for (const byte of publicKey) {
    for (let shift = 7; shift >= 0; shift -= 1) bits.push((byte >> shift) & 1)
  }
  bits.push(0) // extensions = 0
  bits.push(1) // completion tag
  while (bits.length % 8 !== 0) bits.push(0)
  const dataBytes: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8; j += 1) byte |= bits[i + j]! << (7 - j)
    dataBytes.push(byte)
  }
  const repr = new Uint8Array(2 + dataBytes.length)
  repr[0] = 0 // d1: 0 refs
  repr[1] = 81 // d2: ceil(322/8)+floor(322/8)
  repr.set(dataBytes, 2)
  return sha256(repr)
}

/** StateInit cell hash (5 type bits + code/data refs). */
function tonStateInitHash(codeHash: Uint8Array, codeDepth: number, dataHash: Uint8Array): Uint8Array {
  const repr = new Uint8Array(2 + 1 + 4 + 32 + 32)
  repr[0] = 2 // d1: 2 refs
  repr[1] = 1 // d2
  repr[2] = 0x34 // 00110 + completion tag
  repr[3] = (codeDepth >> 8) & 0xff
  repr[4] = codeDepth & 0xff
  repr[5] = 0 // data depth = 0
  repr[6] = 0
  repr.set(codeHash, 7)
  repr.set(dataHash, 39)
  return sha256(repr)
}

/** User-friendly TON address (base64url, tag + workchain + hash + CRC16). */
function tonEncodeAddress(workchain: number, hash: Uint8Array, bounceable: boolean): string {
  const tag = bounceable ? 0x11 : 0x51
  const addr = new Uint8Array(36)
  addr[0] = tag
  addr[1] = workchain & 0xff
  addr.set(hash, 2)
  const crc = crc16ccitt(addr.subarray(0, 34))
  addr[34] = (crc >> 8) & 0xff
  addr[35] = crc & 0xff
  return Buffer.from(addr).toString('base64url')
}

/** CRC16/CCITT (poly 0x1021, init 0) — TON address checksum. */
function crc16ccitt(data: Uint8Array): number {
  let crc = 0
  for (const byte of data) {
    crc ^= byte << 8
    for (let j = 0; j < 8; j += 1) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff
    }
  }
  return crc
}
