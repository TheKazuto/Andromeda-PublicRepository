// OAuth — PKCE (RFC 7636) helpers.

import { createHash, randomBytes } from 'node:crypto'

const VERIFIER_BYTES = 32

export interface PkcePair {
  codeVerifier: string
  codeChallenge: string
  codeChallengeMethod: 'S256'
}

export function generatePkcePair(): PkcePair {
  const codeVerifier = randomBytes(VERIFIER_BYTES).toString('base64url')
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' }
}

export function verifyPkceChallenge(codeVerifier: string, codeChallenge: string): boolean {
  const expected = createHash('sha256').update(codeVerifier).digest('base64url')
  return expected === codeChallenge
}

export function generateOauthState(): string {
  return randomBytes(32).toString('base64url')
}
