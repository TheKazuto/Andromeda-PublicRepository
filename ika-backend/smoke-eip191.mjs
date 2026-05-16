// Smoke test do caminho EIP-191 admin/submit.
// Run from ika-backend dir: node smoke-eip191.mjs
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { randomBytes } from 'node:crypto'

const API_BASE = 'https://api.andromedainfra.pro'
const API_KEY = 'sk_live_q9foKOCpfXOXpUViBWZoXnKzEM8qtX3vM4bVwJE4'

const b64 = (u8) => Buffer.from(u8).toString('base64')
const b64d = (s) => new Uint8Array(Buffer.from(s, 'base64'))
const hex = (u8) => Buffer.from(u8).toString('hex')

// @noble/curves v2 sign({ format: 'recovered' }) returns 65B = recovery_id(1) || r(32) || s(32).
// Solana secp256k1 precompile expects 65B = r(32) || s(32) || recovery_id(1).
function rearrangeSig(recoveredSig, vOffset = 0) {
  if (recoveredSig.length !== 65) throw new Error(`unexpected sig length ${recoveredSig.length}`)
  const out = new Uint8Array(65)
  out.set(recoveredSig.slice(1, 33), 0)  // r
  out.set(recoveredSig.slice(33, 65), 32) // s
  out[64] = recoveredSig[0] + vOffset      // recovery_id (+27 for Ethereum convention)
  return out
}

// IMPORTANT: @noble/curves v2 sign() defaults to prehash:true (sha256 of input).
// We want to sign the digest DIRECTLY, so pass prehash:false.
function signEip191(challenge, privKey) {
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${challenge.length}`, 'utf8')
  const hash = keccak_256(Buffer.concat([prefix, Buffer.from(challenge)]))
  const recovered = secp256k1.sign(hash, privKey, { format: 'recovered', prehash: false })
  return rearrangeSig(recovered, 27) // Ethereum v = recovery_id + 27
}

function signRaw(challenge, privKey) {
  const hash = keccak_256(Buffer.from(challenge))
  const recovered = secp256k1.sign(hash, privKey, { format: 'recovered', prehash: false })
  return rearrangeSig(recovered, 0) // raw recovery_id (0 or 1)
}

// 1. EVM keypair
const privKey = randomBytes(32)
const pubKeyUncompressed = secp256k1.getPublicKey(privKey, false)
const ethAddress = keccak_256(pubKeyUncompressed.slice(1)).slice(12)
console.log('EVM eth_address: 0x' + hex(ethAddress))

// 2. Create dWallet
console.log('\n=== POST /v1/dwallet/create ===')
const ts = Date.now()
const createResp = await fetch(`${API_BASE}/v1/dwallet/create`, {
  method: 'POST',
  headers: { 'X-Api-Key': API_KEY, 'Content-Type': 'application/json', 'Idempotency-Key': `smoke-eip191-create-${ts}` },
  body: JSON.stringify({
    passphrase: `smoke-eip191-${ts}`,
    curve: 'Curve25519',
    attachRecoveryPolicy: true,
    primaryRecoveryOwner: { scheme: 1, identifierBase64: b64(ethAddress) },
  }),
})
const createJson = await createResp.json()
console.log(JSON.stringify(createJson, null, 2))
if (!createJson.success) process.exit(1)
const { dwalletAddress, policyAddress, initAuthorityHashBase64, signable, recoverable, policyAttachWarning } = createJson.data
console.log('signable:', signable, 'recoverable:', recoverable, 'warning:', policyAttachWarning || '—')
if (!initAuthorityHashBase64) { console.error('NO initAuthorityHashBase64 — backend tweak 2 not deployed?'); process.exit(1) }

// 3. Generate dummy Ed25519 member to add
const memberPubkey = randomBytes(32)
const member = { scheme: 0, identifierBase64: b64(memberPubkey) }
console.log('\ndummy member pubkey (Ed25519):', hex(memberPubkey))

// 4. admin/challenge
console.log('\n=== POST /v1/recovery/policy/admin/challenge ===')
const challResp = await fetch(`${API_BASE}/v1/recovery/policy/admin/challenge`, {
  method: 'POST',
  headers: { 'X-Api-Key': API_KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    dwalletAddress,
    initAuthorityHashBase64,
    action: { type: 'add_member', member },
  }),
})
const challJson = await challResp.json()
console.log(JSON.stringify(challJson, null, 2))
if (!challJson.success) process.exit(1)
const { challengeBase64, expectedNonce, primaryScheme } = challJson.data
const challenge = b64d(challengeBase64)
console.log('challenge (hex):', hex(challenge), '  primaryScheme:', primaryScheme)

// 5. Try EIP-191 sign first
async function submit(variantName, signatureBytes) {
  console.log(`\n=== POST /admin/submit (${variantName}) ===`)
  const r = await fetch(`${API_BASE}/v1/recovery/policy/admin/submit`, {
    method: 'POST',
    headers: {
      'X-Api-Key': API_KEY,
      'Content-Type': 'application/json',
      'Idempotency-Key': `smoke-admin-submit-${variantName}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    },
    body: JSON.stringify({
      dwalletAddress,
      initAuthorityHashBase64,
      action: { type: 'add_member', member },
      primarySignatureBase64: b64(signatureBytes),
      expectedNonce: expectedNonce.toString(),
    }),
  })
  const j = await r.json()
  console.log(JSON.stringify(j, null, 2))
  return j
}

const sigEip191 = signEip191(challenge, privKey)
console.log('\nEIP-191 sig hex (r||s||v=recovery+27):', hex(sigEip191))
const submitJsonEip191 = await submit('EIP-191', sigEip191)

if (submitJsonEip191.success) {
  console.log('\n✅ EIP-191 PATH WORKS')
} else {
  // try raw
  const sigRaw = signRaw(challenge, privKey)
  console.log('\nraw sig hex (r||s||v=recovery):', hex(sigRaw))
  const submitJsonRaw = await submit('RAW (no EIP-191 prefix)', sigRaw)
  if (submitJsonRaw.success) {
    console.log('\n✅ RAW PATH WORKS — MetaMask personal_sign WILL NOT WORK; we need raw signing.')
  } else {
    console.log('\n❌ BOTH paths failed — need deeper debug.')
  }
}
