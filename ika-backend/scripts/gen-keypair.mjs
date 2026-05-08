import { ed25519 } from '@noble/curves/ed25519.js'
import { writeFileSync } from 'node:fs'
import bs58 from 'bs58'

const secretKey = ed25519.utils.randomSecretKey()
const publicKey = ed25519.getPublicKey(secretKey)

const combined = new Uint8Array(64)
combined.set(secretKey, 0)
combined.set(publicKey, 32)

const path = process.argv[2]
if (!path) {
  console.error('usage: node scripts/gen-keypair.mjs <output-path>')
  process.exit(1)
}
writeFileSync(path, JSON.stringify(Array.from(combined)))
console.log('address:', bs58.encode(publicKey))
console.log('saved to:', path)
