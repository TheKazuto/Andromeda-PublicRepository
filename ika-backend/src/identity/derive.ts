// Identity layer — canonical walletAddress derivation.
//
// Goal: given a verified identity, produce a deterministic 64-char hex string
// that downstream layers consume as `walletAddress`. The same identity always
// yields the same address; different providers cannot collide because the
// canonical string carries a provider prefix.

import { createHash } from 'node:crypto'
import type { CanonicalIdentitySubject, IdentityProvider, VerifiedIdentity } from './types.js'

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export function canonicalIdentityString(identity: VerifiedIdentity): string {
  switch (identity.provider) {
    case 'oauth-google':
      return `oauth:google:${identity.sub}`
    case 'oauth-apple':
      return `oauth:apple:${identity.sub}`
    case 'oauth-twitter':
      return `oauth:twitter:${identity.sub}`
    case 'oauth-github':
      return `oauth:github:${identity.sub}`
    case 'email':
      return `email:${normalizeEmail(identity.email)}`
    case 'passkey-prf':
      return `passkey:${identity.prfOutputHex.toLowerCase()}`
  }
}

export function canonicalSubject(identity: VerifiedIdentity): CanonicalIdentitySubject {
  switch (identity.provider) {
    case 'oauth-google':
    case 'oauth-apple':
    case 'oauth-twitter':
    case 'oauth-github':
      return { provider: identity.provider, subject: identity.sub }
    case 'email':
      return { provider: 'email', subject: normalizeEmail(identity.email) }
    case 'passkey-prf':
      return { provider: 'passkey-prf', subject: identity.prfOutputHex.toLowerCase() }
  }
}

export function deriveWalletAddress(identity: VerifiedIdentity): string {
  const canonical = canonicalIdentityString(identity)
  return createHash('sha256').update(canonical, 'utf8').digest('hex')
}

export function deriveWalletAddressFromSubject(
  provider: IdentityProvider,
  subject: string,
): string {
  let canonical: string
  switch (provider) {
    case 'oauth-google':
      canonical = `oauth:google:${subject}`
      break
    case 'oauth-apple':
      canonical = `oauth:apple:${subject}`
      break
    case 'oauth-twitter':
      canonical = `oauth:twitter:${subject}`
      break
    case 'oauth-github':
      canonical = `oauth:github:${subject}`
      break
    case 'email':
      canonical = `email:${normalizeEmail(subject)}`
      break
    case 'passkey-prf':
      canonical = `passkey:${subject.toLowerCase()}`
      break
  }
  return createHash('sha256').update(canonical, 'utf8').digest('hex')
}
