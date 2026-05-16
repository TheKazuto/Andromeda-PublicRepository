// Recovery — Ed25519 "raw bytes" scheme.
// Used by Solana (Phantom, Solflare, Backpack) and any chain where the
// wallet calls Ed25519.sign(privKey, utf8Bytes(message)) without domain
// separation. Address IS the pubkey (base58 of 32 bytes).

import { ed25519 } from '@noble/curves/ed25519.js'
import bs58 from 'bs58'
import {
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const PUBKEY_LENGTH = 32
const SIGNATURE_LENGTH = 64

function decodeBase58Pubkey(walletAddress: string): Uint8Array | null {
  try {
    const decoded = bs58.decode(walletAddress.trim())
    if (decoded.length !== PUBKEY_LENGTH) return null
    return decoded
  } catch {
    return null
  }
}

export const ed25519RawVerifier: SchemeVerifier = {
  scheme: 'ed25519-raw',
  async verify(input: VerifyInput): Promise<boolean> {
    const pubkey = decodeBase58Pubkey(input.walletAddress)
    if (!pubkey) return false
    const signature = decodeSignatureBytes(input.signature)
    if (!signature || signature.length !== SIGNATURE_LENGTH) return false
    const messageBytes = Buffer.from(input.message, 'utf8')
    try {
      return ed25519.verify(signature, messageBytes, pubkey)
    } catch {
      return false
    }
  },
}

registerVerifier(ed25519RawVerifier)
