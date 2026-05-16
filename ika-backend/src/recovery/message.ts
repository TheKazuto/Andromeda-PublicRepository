import { randomBytes, createHash } from 'node:crypto'

const VERSION = 'andromeda-ika-recovery-v1'

export function generateNonce(): string {
  return randomBytes(16).toString('base64url')
}

export function buildCanonicalMessage(input: {
  appId: string
  walletAddress: string
  scheme: string
  nonce: string
  issuedAtIso: string
  expiresAtIso: string
}): string {
  return [
    `Version: ${VERSION}`,
    `App: ${input.appId}`,
    `Wallet: ${input.walletAddress}`,
    `Scheme: ${input.scheme}`,
    `Nonce: ${input.nonce}`,
    `IssuedAt: ${input.issuedAtIso}`,
    `ExpiresAt: ${input.expiresAtIso}`,
    'Action: prove ownership for andromeda recovery',
  ].join('\n')
}

export function messageHash32(message: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(Buffer.from(message, 'utf8')).digest())
}
