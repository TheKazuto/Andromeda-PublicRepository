import { describe, it, expect, beforeAll } from 'vitest'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256, sha3_256 } from '@noble/hashes/sha3.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { bech32 } from 'bech32'
import bs58 from 'bs58'
import { sr25519PairFromSeed, sr25519Sign, encodeAddress, cryptoWaitReady } from '@polkadot/util-crypto'
import { buildCanonicalMessage } from '../../message.js'
import { getVerifier, loadAllVerifiers, _resetRecoveryRegistry, type SchemeId } from '../index.js'

// Each discovery verifier reconstructs the bytes the wallet actually signed
// (per the scheme's domain-separation rules) and checks them against an
// address-or-pubkey-derived key. This suite forges a *valid* signature for
// each scheme (replicating its signed-bytes construction) and asserts:
//   valid signature                         → true
//   one byte flipped in the signature       → false
//   correct signature, wrong address/pubkey → false

const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex')
const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'utf8'))
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n)
const sha256 = (u: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(u).digest())
const dsha256 = (u: Uint8Array): Uint8Array => sha256(sha256(u))
const h160 = (u: Uint8Array): Uint8Array => new Uint8Array(ripemd160(sha256(u)))

function canonical(appId: string, walletAddress: string, scheme: string, nonce: string): string {
  return buildCanonicalMessage({
    appId,
    walletAddress,
    scheme,
    nonce,
    issuedAtIso: '2026-01-01T00:00:00.000Z',
    expiresAtIso: '2026-01-01T00:05:00.000Z',
  })
}

function flipByte(hexStr: string, index = 0): string {
  const b = Buffer.from(hexStr, 'hex')
  b[index] = b[index]! ^ 0xff
  return b.toString('hex')
}

// secp256k1 recoverable sign → [recovery(1), r(32), s(32)]
function signRecoverable(msgHash: Uint8Array, priv: Uint8Array): { recovery: number; rs: Uint8Array } {
  const recovered = secp256k1.sign(msgHash, priv, { format: 'recovered', prehash: false }) as Uint8Array
  return { recovery: recovered[0]!, rs: recovered.subarray(1) }
}

interface Vector {
  scheme: SchemeId
  walletAddress: string
  message: string
  signature: string
  publicKey?: string
  /** A different address/pubkey that must NOT verify. */
  wrongAddress?: string
  wrongPublicKey?: string
}

// ── ed25519-raw (Solana) ─────────────────────────────────────────
function vEd25519Raw(): Vector {
  const sk = seed(1)
  const pk = ed25519.getPublicKey(sk)
  const walletAddress = bs58.encode(pk)
  const message = canonical('app', walletAddress, 'ed25519-raw', 'sol-nonce-1')
  const sig = ed25519.sign(utf8(message), sk)
  return { scheme: 'ed25519-raw', walletAddress, message, signature: hex(sig), wrongAddress: bs58.encode(ed25519.getPublicKey(seed(2))) }
}

// ── secp256k1-eip191 (EVM) ───────────────────────────────────────
function evmAddress(priv: Uint8Array): string {
  const uncompressed = secp256k1.getPublicKey(priv, false) // 65 bytes (0x04 || x || y)
  const hash = keccak_256(uncompressed.subarray(1))
  return '0x' + Buffer.from(hash.subarray(hash.length - 20)).toString('hex')
}
function vEip191(): Vector {
  const priv = seed(3)
  const walletAddress = evmAddress(priv)
  const message = canonical('app', walletAddress, 'secp256k1-eip191', 'evm-nonce')
  const prefixed = Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${Buffer.byteLength(message)}`, 'utf8'), Buffer.from(message, 'utf8')])
  const digest = keccak_256(prefixed)
  const { recovery, rs } = signRecoverable(digest, priv)
  const sig65 = Buffer.concat([rs, Buffer.from([27 + recovery])]) // r || s || v
  return { scheme: 'secp256k1-eip191', walletAddress, message, signature: hex(sig65), wrongAddress: evmAddress(seed(4)) }
}

// ── ed25519-aptos (AIP-62) ───────────────────────────────────────
function aptosAuthKeyHex(pk: Uint8Array): string {
  const buf = new Uint8Array(pk.length + 1)
  buf.set(pk, 0)
  buf[pk.length] = 0x00 // single-key scheme
  return Buffer.from(sha3_256(buf)).toString('hex')
}
function vAptos(): Vector {
  const sk = seed(5)
  const pk = ed25519.getPublicKey(sk)
  const authKey = aptosAuthKeyHex(pk)
  const walletAddress = '0x' + authKey
  const message = canonical('app', walletAddress, 'ed25519-aptos', 'aptos-nonce')
  const fullMessage = [`APTOS\naddress: 0x${authKey}`, `application: app`, `nonce: aptos-nonce`, `message: ${message}`].join('\n')
  const signedBytes = sha3_256(utf8(fullMessage))
  const sig = ed25519.sign(signedBytes, sk)
  return { scheme: 'ed25519-aptos', walletAddress, message, signature: hex(sig), publicKey: hex(pk), wrongPublicKey: hex(ed25519.getPublicKey(seed(6))) }
}

// ── ed25519-near (NEP-413) ───────────────────────────────────────
const NEAR_OFF_CHAIN_TAG = 2147484061
function nearBorsh(message: string, nonce32: Uint8Array, recipient: string): Uint8Array {
  const messageBytes = Buffer.from(message, 'utf8')
  const recipientBytes = Buffer.from(recipient, 'utf8')
  const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b }
  return new Uint8Array(Buffer.concat([u32(NEAR_OFF_CHAIN_TAG), u32(messageBytes.length), messageBytes, Buffer.from(nonce32), u32(recipientBytes.length), recipientBytes, Buffer.from([0])]))
}
function vNear(): Vector {
  const sk = seed(7)
  const pk = ed25519.getPublicKey(sk)
  const nonceStr = 'near-nonce-XYZ'
  const walletAddress = 'alice.near'
  const message = canonical('app', walletAddress, 'ed25519-near', nonceStr)
  const nonce32 = sha256(utf8(nonceStr))
  const signedBytes = sha256(nearBorsh(message, nonce32, 'app'))
  const sig = ed25519.sign(signedBytes, sk)
  return { scheme: 'ed25519-near', walletAddress, message, signature: hex(sig), publicKey: 'ed25519:' + bs58.encode(pk), wrongPublicKey: 'ed25519:' + bs58.encode(ed25519.getPublicKey(seed(8))) }
}

// ── secp256k1-adr036 (Cosmos) ────────────────────────────────────
function cosmosAddress(compressedPk: Uint8Array, prefix = 'cosmos'): string {
  return bech32.encode(prefix, bech32.toWords(h160(compressedPk)))
}
function vAdr036(): Vector {
  const priv = seed(9)
  const pk = secp256k1.getPublicKey(priv, true) // compressed (33)
  const walletAddress = cosmosAddress(pk)
  const message = canonical('app', walletAddress, 'secp256k1-adr036', 'cosmos-nonce')
  const dataB64 = Buffer.from(message, 'utf8').toString('base64')
  const signDoc =
    '{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"' +
    dataB64 + '","signer":"' + walletAddress + '"}}],"sequence":"0"}'
  const digest = sha256(utf8(signDoc))
  const sig = secp256k1.sign(digest, priv, { prehash: false }) as Uint8Array // 64-byte compact
  return { scheme: 'secp256k1-adr036', walletAddress, message, signature: hex(sig), publicKey: hex(pk), wrongPublicKey: hex(secp256k1.getPublicKey(seed(10), true)) }
}

// ── secp256k1-bitcoin (BIP-137, P2PKH) ───────────────────────────
function p2pkh(compressedPk: Uint8Array): string {
  const payload = Buffer.concat([Buffer.from([0x00]), Buffer.from(h160(compressedPk))])
  return bs58.encode(Buffer.concat([payload, Buffer.from(dsha256(payload).subarray(0, 4))]))
}
function bitcoinMagicHash(message: string): Uint8Array {
  const messageBytes = Buffer.from(message, 'utf8')
  const lenBuf = messageBytes.length < 0xfd ? Buffer.from([messageBytes.length]) : (() => { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(messageBytes.length, 1); return b })()
  return dsha256(new Uint8Array(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8'), lenBuf, messageBytes])))
}
function vBitcoin(): Vector {
  const priv = seed(11)
  const pk = secp256k1.getPublicKey(priv, true)
  const walletAddress = p2pkh(pk)
  const message = canonical('app', walletAddress, 'secp256k1-bitcoin', 'btc-nonce')
  const digest = bitcoinMagicHash(message)
  const { recovery, rs } = signRecoverable(digest, priv)
  const header = 31 + recovery // compressed-pubkey header range (31..34)
  const sig65 = Buffer.concat([Buffer.from([header]), rs])
  return { scheme: 'secp256k1-bitcoin', walletAddress, message, signature: hex(sig65), wrongAddress: p2pkh(secp256k1.getPublicKey(seed(12), true)) }
}

// ── sr25519-substrate ────────────────────────────────────────────
let vSr: Vector
function buildSrVector(): Vector {
  const pair = sr25519PairFromSeed(seed(13))
  const walletAddress = encodeAddress(pair.publicKey)
  const message = canonical('app', walletAddress, 'sr25519-substrate', 'sub-nonce')
  const sig = sr25519Sign(utf8(`<Bytes>${message}</Bytes>`), pair)
  return { scheme: 'sr25519-substrate', walletAddress, message, signature: hex(sig), wrongAddress: encodeAddress(sr25519PairFromSeed(seed(14)).publicKey) }
}

describe('recovery/discovery verifiers — valid / tampered / wrong-key', () => {
  beforeAll(async () => {
    _resetRecoveryRegistry()
    await loadAllVerifiers()
    await cryptoWaitReady()
    vSr = buildSrVector()
  })

  function vectors(): Vector[] {
    return [vEd25519Raw(), vEip191(), vAptos(), vNear(), vAdr036(), vBitcoin(), vSr]
  }

  it('accepts a correctly-forged signature for every scheme', async () => {
    for (const v of vectors()) {
      const verifier = getVerifier(v.scheme)!
      const ok = await verifier.verify({
        message: v.message,
        walletAddress: v.walletAddress,
        signature: v.signature,
        ...(v.publicKey ? { publicKey: v.publicKey } : {}),
      })
      expect(ok, `${v.scheme} should accept a valid signature`).toBe(true)
    }
  })

  it('rejects a signature with one byte flipped', async () => {
    for (const v of vectors()) {
      const verifier = getVerifier(v.scheme)!
      // flip a byte well inside the r/s region (avoid the BIP-137 header byte)
      const bad = flipByte(v.signature, v.scheme === 'secp256k1-bitcoin' ? 4 : 2)
      const ok = await verifier.verify({
        message: v.message,
        walletAddress: v.walletAddress,
        signature: bad,
        ...(v.publicKey ? { publicKey: v.publicKey } : {}),
      })
      expect(ok, `${v.scheme} should reject a tampered signature`).toBe(false)
    }
  })

  it('rejects a valid signature presented against the wrong address/pubkey', async () => {
    for (const v of vectors()) {
      const verifier = getVerifier(v.scheme)!
      const ok = await verifier.verify({
        message: v.message,
        walletAddress: v.wrongAddress ?? v.walletAddress,
        signature: v.signature,
        ...(v.wrongPublicKey ? { publicKey: v.wrongPublicKey } : v.publicKey ? { publicKey: v.publicKey } : {}),
      })
      expect(ok, `${v.scheme} should reject against the wrong key`).toBe(false)
    }
  })

  it('rejects garbage signatures for every scheme', async () => {
    for (const scheme of ['ed25519-raw', 'ed25519-near', 'ed25519-aptos', 'secp256k1-eip191', 'secp256k1-adr036', 'secp256k1-bitcoin', 'sr25519-substrate'] as const) {
      const verifier = getVerifier(scheme)!
      expect(await verifier.verify({ message: 'whatever', walletAddress: 'not-an-address', signature: 'zz', publicKey: 'zz' })).toBe(false)
      expect(await verifier.verify({ message: 'whatever', walletAddress: 'not-an-address', signature: '00', publicKey: '00' })).toBe(false)
    }
  })
})
