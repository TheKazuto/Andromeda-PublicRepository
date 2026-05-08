// Recovery — Substrate (Polkadot/Kusama) personal-message scheme.

import { decodeAddress, signatureVerify } from '@polkadot/util-crypto'
import {
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

function wrapSubstrateMessage(message: string): Uint8Array {
  return new Uint8Array(Buffer.from(`<Bytes>${message}</Bytes>`, 'utf8'))
}

export const sr25519SubstrateVerifier: SchemeVerifier = {
  scheme: 'sr25519-substrate',
  async verify(input: VerifyInput): Promise<boolean> {
    let pubkey: Uint8Array
    try {
      pubkey = decodeAddress(input.walletAddress.trim())
    } catch {
      return false
    }
    if (pubkey.length !== 32) return false
    const sigBytes = decodeSignatureBytes(input.signature)
    if (!sigBytes) return false
    const wrapped = wrapSubstrateMessage(input.message)
    try {
      const result = signatureVerify(wrapped, sigBytes, pubkey)
      return result.isValid === true
    } catch {
      return false
    }
  },
}

registerVerifier(sr25519SubstrateVerifier)
