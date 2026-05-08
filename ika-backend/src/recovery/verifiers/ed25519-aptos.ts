// Recovery — Aptos personal-message scheme (AIP-62).

import { sha3_256 } from '@noble/hashes/sha3.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  decodePublicKeyBytes,
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const APTOS_PREFIX = 'APTOS\n'
const PUBKEY_LENGTH = 32
const SIGNATURE_LENGTH = 64
const APTOS_AUTH_KEY_SCHEME_SINGLE_KEY = 0x00

function readNonce(message: string): string | null {
  const m = /^Nonce:\s*([A-Za-z0-9_-]+)$/m.exec(message)
  return m ? m[1]!.trim() : null
}

function readAppId(message: string): string | null {
  const m = /^App:\s*(.+)$/m.exec(message)
  return m ? m[1]!.trim() : null
}

function buildFullMessage(input: { walletAddress: string; appId: string; nonce: string; innerMessage: string }): string {
  return [
    `${APTOS_PREFIX}address: ${input.walletAddress}`,
    `application: ${input.appId}`,
    `nonce: ${input.nonce}`,
    `message: ${input.innerMessage}`,
  ].join('\n')
}

function deriveAuthKey(publicKey: Buffer): Buffer {
  const buf = Buffer.alloc(publicKey.length + 1)
  publicKey.copy(buf, 0)
  buf[publicKey.length] = APTOS_AUTH_KEY_SCHEME_SINGLE_KEY
  return Buffer.from(sha3_256(buf))
}

function normalizeAddress(address: string): string {
  let trimmed = address.trim().toLowerCase()
  if (trimmed.startsWith('0x')) trimmed = trimmed.slice(2)
  return trimmed.padStart(64, '0')
}

export const ed25519AptosVerifier: SchemeVerifier = {
  scheme: 'ed25519-aptos',
  async verify(input: VerifyInput): Promise<boolean> {
    const nonce = readNonce(input.message)
    const appId = readAppId(input.message)
    if (!nonce || !appId) return false
    const pubkey = decodePublicKeyBytes(input.publicKey)
    if (!pubkey || pubkey.length !== PUBKEY_LENGTH) return false
    const signature = decodeSignatureBytes(input.signature)
    if (!signature || signature.length !== SIGNATURE_LENGTH) return false
    const expectedAuthKey = deriveAuthKey(pubkey).toString('hex')
    if (normalizeAddress(input.walletAddress) !== expectedAuthKey) return false
    const fullMessage = buildFullMessage({
      walletAddress: '0x' + expectedAuthKey,
      appId,
      nonce,
      innerMessage: input.message,
    })
    const signedBytes = sha3_256(Buffer.from(fullMessage, 'utf8'))
    try {
      return ed25519.verify(signature, signedBytes, pubkey)
    } catch {
      return false
    }
  },
}

registerVerifier(ed25519AptosVerifier)
