// Recovery — EVM personal-message scheme (EIP-191).
// Covers all EVM-compatible chains.

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import {
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const EVM_ADDRESS_BYTES = 20
const SIGNATURE_LENGTH = 65

function eip191Hash(message: string): Uint8Array {
  const messageBytes = Buffer.from(message, 'utf8')
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${messageBytes.length}`, 'utf8')
  return keccak_256(Buffer.concat([prefix, messageBytes]))
}

function evmAddressFromPubkey(pubkeyUncompressed: Uint8Array): string {
  const xy = pubkeyUncompressed.length === 65 ? pubkeyUncompressed.slice(1) : pubkeyUncompressed
  const hash = keccak_256(xy)
  return '0x' + Buffer.from(hash.slice(hash.length - EVM_ADDRESS_BYTES)).toString('hex')
}

function normalizeEvmAddress(value: string): string | null {
  const trimmed = value.trim().toLowerCase()
  if (!/^0x[0-9a-f]{40}$/.test(trimmed)) return null
  return trimmed
}

export const secp256k1Eip191Verifier: SchemeVerifier = {
  scheme: 'secp256k1-eip191',
  async verify(input: VerifyInput): Promise<boolean> {
    const expectedAddress = normalizeEvmAddress(input.walletAddress)
    if (!expectedAddress) return false
    const sigBytes = decodeSignatureBytes(input.signature)
    if (!sigBytes || sigBytes.length !== SIGNATURE_LENGTH) return false
    const r = sigBytes.subarray(0, 32)
    const s = sigBytes.subarray(32, 64)
    const vByte = sigBytes[64]!
    let recoveryId: number
    if (vByte === 27 || vByte === 28) recoveryId = vByte - 27
    else if (vByte === 0 || vByte === 1) recoveryId = vByte
    else if (vByte >= 35) recoveryId = (vByte - 35) % 2
    else return false
    const hash = eip191Hash(input.message)
    try {
      const recoveredFormat = Buffer.concat([Buffer.from([recoveryId]), r, s])
      const compressed = secp256k1.recoverPublicKey(recoveredFormat, hash, { prehash: false })
      const uncompressed = secp256k1.Point.fromBytes(compressed).toBytes(false)
      return evmAddressFromPubkey(uncompressed) === expectedAddress
    } catch {
      return false
    }
  },
}

registerVerifier(secp256k1Eip191Verifier)
