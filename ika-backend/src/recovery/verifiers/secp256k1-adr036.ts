// Recovery — Cosmos personal-message scheme (ADR-036).
// Covers every Cosmos-SDK chain (Cosmos Hub, Osmosis, Sei, Injective, etc.).

import { createHash } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { bech32 } from 'bech32'
import { ripemd160 } from '@noble/hashes/legacy.js'
import {
  decodePublicKeyBytes,
  decodeSignatureBytes,
  registerVerifier,
  type SchemeVerifier,
  type VerifyInput,
} from './index.js'

const COMPRESSED_PUBKEY_LENGTH = 33
const SIGNATURE_LENGTH = 64

function decodeBech32Address(address: string): { prefix: string; data: Uint8Array } | null {
  try {
    const decoded = bech32.decode(address.trim())
    const data = bech32.fromWords(decoded.words)
    return { prefix: decoded.prefix, data: new Uint8Array(data) }
  } catch {
    return null
  }
}

function cosmosAddressFromPubkey(pubkeyCompressed: Buffer): Buffer {
  const sha = createHash('sha256').update(pubkeyCompressed).digest()
  return Buffer.from(ripemd160(sha))
}

function buildAdr036SignDocHash(input: { signer: string; data: string }): Uint8Array {
  const dataBase64 = Buffer.from(input.data, 'utf8').toString('base64')
  const signDoc =
    '{"account_number":"0",' +
    '"chain_id":"",' +
    '"fee":{"amount":[],"gas":"0"},' +
    '"memo":"",' +
    '"msgs":[{"type":"sign/MsgSignData","value":{"data":"' + dataBase64 + '","signer":"' + input.signer + '"}}],' +
    '"sequence":"0"}'
  return new Uint8Array(createHash('sha256').update(Buffer.from(signDoc, 'utf8')).digest())
}

export const secp256k1Adr036Verifier: SchemeVerifier = {
  scheme: 'secp256k1-adr036',
  async verify(input: VerifyInput): Promise<boolean> {
    const decoded = decodeBech32Address(input.walletAddress)
    if (!decoded || decoded.data.length !== 20) return false
    const pubkey = decodePublicKeyBytes(input.publicKey)
    if (!pubkey || pubkey.length !== COMPRESSED_PUBKEY_LENGTH) return false
    const expectedHash = cosmosAddressFromPubkey(pubkey)
    if (Buffer.compare(expectedHash, Buffer.from(decoded.data)) !== 0) return false
    const sigBytes = decodeSignatureBytes(input.signature)
    if (!sigBytes || sigBytes.length !== SIGNATURE_LENGTH) return false
    const digest = buildAdr036SignDocHash({ signer: input.walletAddress.trim(), data: input.message })
    try {
      return secp256k1.verify(sigBytes, digest, pubkey, { format: 'compact', prehash: false })
    } catch {
      return false
    }
  },
}

registerVerifier(secp256k1Adr036Verifier)
