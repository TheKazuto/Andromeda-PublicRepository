// Identity layer — session creation pipeline.
// verified identity → canonical subject → walletAddress → upsert → JWT + refresh.

import { canonicalSubject, deriveWalletAddress } from './derive.js'
import { issueProductJwt, persistRefreshToken } from './jwt.js'
import { resolveIdentityForLogin, upsertIdentity } from './store.js'
import { getIdentityConfig } from './config.js'
import type {
  IdentityProvider,
  IdentityRecordData,
  VerifiedIdentity,
} from './types.js'

export interface SessionContext {
  userAgent?: string | null
  ipHash?: string | null
}

export interface IdentitySession {
  walletAddress: string
  productJwt: { token: string; expiresAt: string; jwtId: string }
  refreshToken: { token: string; expiresAt: string }
  isNew: boolean
  primaryProvider: IdentityProvider
  provider: IdentityProvider
}

function buildPersistableData(identity: VerifiedIdentity): IdentityRecordData {
  const { persistence } = getIdentityConfig()
  const data: IdentityRecordData = {}
  switch (identity.provider) {
    case 'oauth-google':
    case 'oauth-apple':
    case 'oauth-twitter':
    case 'oauth-github':
      if (persistence.persistEmail && identity.email) data.email = identity.email
      if (persistence.persistDisplayName && identity.displayName) data.displayName = identity.displayName
      break
    case 'email':
      if (persistence.persistEmail) data.email = identity.email
      break
    case 'passkey-prf':
      break
  }
  return data
}

export async function resolvePrimaryWalletAddress(identity: VerifiedIdentity): Promise<{
  walletAddress: string
  primaryProvider: IdentityProvider
}> {
  const subject = canonicalSubject(identity)
  // Single CTE: alias→primary OR direct identity, in one roundtrip.
  const resolved = await resolveIdentityForLogin(subject.provider, subject.subject)
  if (resolved) return resolved
  // Truly new login → derive deterministic wallet from identity claims.
  return { walletAddress: deriveWalletAddress(identity), primaryProvider: subject.provider }
}

export async function createSessionForIdentity(
  identity: VerifiedIdentity,
  context: SessionContext = {},
): Promise<IdentitySession> {
  const { walletAddress, primaryProvider } = await resolvePrimaryWalletAddress(identity)
  const subject = canonicalSubject(identity)

  const upsert = await upsertIdentity({
    walletAddress,
    primaryProvider,
    primarySubject: subject.subject,
    data: buildPersistableData(identity),
  })

  const [productJwt, refresh] = await Promise.all([
    issueProductJwt({
      walletAddress,
      provider: subject.provider,
      primaryProvider,
    }),
    persistRefreshToken({
      walletAddress,
      userAgent: context.userAgent ?? null,
      ipHash: context.ipHash ?? null,
    }),
  ])

  return {
    walletAddress,
    productJwt,
    refreshToken: { token: refresh.token, expiresAt: refresh.expiresAt.toISOString() },
    isNew: upsert.isNew,
    primaryProvider,
    provider: subject.provider,
  }
}
