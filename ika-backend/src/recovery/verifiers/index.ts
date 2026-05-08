// Recovery — scheme verifier abstraction.
//
// A SchemeVerifier knows how to take a (message, walletAddress, signature)
// triple, reconstruct the bytes the wallet actually signed (per the
// scheme's domain-separation rules), and verify the signature against
// either an explicit publicKey or one decoded/recovered from walletAddress.

export type SchemeId =
  | 'ed25519-raw'
  | 'ed25519-near'
  | 'ed25519-aptos'
  | 'secp256k1-eip191'
  | 'secp256k1-adr036'
  | 'secp256k1-bitcoin'
  | 'sr25519-substrate'

export const SCHEME_IDS: ReadonlyArray<SchemeId> = [
  'ed25519-raw',
  'ed25519-near',
  'ed25519-aptos',
  'secp256k1-eip191',
  'secp256k1-adr036',
  'secp256k1-bitcoin',
  'sr25519-substrate',
] as const
const SCHEME_ID_SET = new Set<string>(SCHEME_IDS)

export interface VerifyInput {
  message: string
  walletAddress: string
  signature: string
  publicKey?: string
}

export interface SchemeVerifier {
  readonly scheme: SchemeId
  verify(input: VerifyInput): Promise<boolean>
}

const registry = new Map<SchemeId, SchemeVerifier>()
let loadPromise: Promise<void> | null = null

export function registerVerifier(verifier: SchemeVerifier): void {
  registry.set(verifier.scheme, verifier)
}

export function getVerifier(scheme: string): SchemeVerifier | null {
  if (!SCHEME_ID_SET.has(scheme)) return null
  return registry.get(scheme as SchemeId) ?? null
}

export function isKnownScheme(value: unknown): value is SchemeId {
  return typeof value === 'string' && SCHEME_ID_SET.has(value)
}

export function listRegisteredSchemes(): SchemeId[] {
  return [...registry.keys()]
}

export function _resetRecoveryRegistry(): void {
  registry.clear()
}

export function decodeSignatureBytes(signature: string): Buffer | null {
  if (typeof signature !== 'string' || signature.length === 0) return null
  const trimmed = signature.trim()
  if (/^(0x)?[0-9a-fA-F]+$/.test(trimmed)) {
    const stripped = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed
    if (stripped.length === 0 || stripped.length % 2 !== 0) return null
    return Buffer.from(stripped, 'hex')
  }
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(trimmed)) {
    try { return Buffer.from(trimmed, 'base64url') } catch { /* fallthrough */ }
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    try { return Buffer.from(trimmed, 'base64') } catch { /* fallthrough */ }
  }
  return null
}

export function decodePublicKeyBytes(publicKey: string | undefined): Buffer | null {
  if (publicKey === undefined) return null
  return decodeSignatureBytes(publicKey)
}

export async function loadAllVerifiers(): Promise<void> {
  if (loadPromise) return await loadPromise
  loadPromise = (async () => {
  await import('./ed25519-raw.js')
  await import('./ed25519-near.js')
  await import('./ed25519-aptos.js')
  await import('./secp256k1-eip191.js')
  await import('./secp256k1-adr036.js')
  await import('./secp256k1-bitcoin.js')
  await import('./sr25519-substrate.js')
  })()
  return await loadPromise
}
