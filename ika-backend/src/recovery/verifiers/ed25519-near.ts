// Recovery — NEAR personal-message scheme (NEP-413).
// Borsh-serialized payload over user message + nonce + recipient + tag,
// hashed sha256, signed Ed25519.

import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import bs58 from 'bs58'
import {
  decodePublicKeyBytes,
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const TAG_OFF_CHAIN_MESSAGE = 2147484061
const NEAR_PUBKEY_LENGTH = 32
const SIGNATURE_LENGTH = 64

interface ParsedNearPubkey {
  scheme: 'ed25519'
  bytes: Buffer
}

function parseNearPublicKey(value: string | undefined): ParsedNearPubkey | null {
  if (!value) return null
  const trimmed = value.trim()
  if (trimmed.startsWith('ed25519:')) {
    try {
      const decoded = bs58.decode(trimmed.slice('ed25519:'.length))
      if (decoded.length !== NEAR_PUBKEY_LENGTH) return null
      return { scheme: 'ed25519', bytes: Buffer.from(decoded) }
    } catch {
      return null
    }
  }
  try {
    const decoded = bs58.decode(trimmed)
    if (decoded.length === NEAR_PUBKEY_LENGTH) {
      return { scheme: 'ed25519', bytes: Buffer.from(decoded) }
    }
  } catch { /* fallthrough */ }
  const decoded = decodePublicKeyBytes(trimmed)
  if (decoded && decoded.length === NEAR_PUBKEY_LENGTH) {
    return { scheme: 'ed25519', bytes: decoded }
  }
  return null
}

function deriveNearNonce32(recoveryNonce: string): Buffer {
  return createHash('sha256').update(recoveryNonce, 'utf8').digest()
}

function readRecoveryFields(message: string): { appId: string; nonce: string } | null {
  const appMatch = /^App:\s*(.+)$/m.exec(message)
  const nonceMatch = /^Nonce:\s*([A-Za-z0-9_-]+)$/m.exec(message)
  if (!appMatch || !nonceMatch) return null
  return { appId: appMatch[1]!.trim(), nonce: nonceMatch[1]!.trim() }
}

function borshSerialize(payload: { message: string; nonce: Buffer; recipient: string }): Buffer {
  const messageBytes = Buffer.from(payload.message, 'utf8')
  const recipientBytes = Buffer.from(payload.recipient, 'utf8')
  const u32 = (n: number): Buffer => {
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(n, 0)
    return buf
  }
  return Buffer.concat([
    u32(TAG_OFF_CHAIN_MESSAGE),
    u32(messageBytes.length), messageBytes,
    payload.nonce,
    u32(recipientBytes.length), recipientBytes,
    Buffer.from([0]),
  ])
}

export const ed25519NearVerifier: SchemeVerifier = {
  scheme: 'ed25519-near',
  async verify(input: VerifyInput): Promise<boolean> {
    const fields = readRecoveryFields(input.message)
    if (!fields) return false
    const pubkey = parseNearPublicKey(input.publicKey)
    if (!pubkey) return false
    const signature = decodeSignatureBytes(input.signature)
    if (!signature || signature.length !== SIGNATURE_LENGTH) return false
    const nonce32 = deriveNearNonce32(fields.nonce)
    const payload = borshSerialize({ message: input.message, nonce: nonce32, recipient: fields.appId })
    const signedBytes = createHash('sha256').update(payload).digest()
    try {
      return ed25519.verify(signature, signedBytes, pubkey.bytes)
    } catch {
      return false
    }
  },
}

registerVerifier(ed25519NearVerifier)
