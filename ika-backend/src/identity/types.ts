// Identity layer — shared types.
//
// Opt-in via IKA_IDENTITY_ENABLED. Surface here describes user-mode auth only.
// Service-mode (X-Api-Key) callers continue to pass `body.address` directly.

export type IdentityProvider =
  | 'oauth-google'
  | 'oauth-apple'
  | 'oauth-twitter'
  | 'oauth-github'
  | 'email'
  | 'passkey-prf'

export const IDENTITY_PROVIDERS: ReadonlyArray<IdentityProvider> = [
  'oauth-google',
  'oauth-apple',
  'oauth-twitter',
  'oauth-github',
  'email',
  'passkey-prf',
] as const

export interface VerifiedOauthIdentity {
  provider: 'oauth-google' | 'oauth-apple' | 'oauth-twitter' | 'oauth-github'
  sub: string
  email?: string | null
  displayName?: string | null
}

export interface VerifiedEmailIdentity {
  provider: 'email'
  email: string
}

export interface VerifiedPasskeyIdentity {
  provider: 'passkey-prf'
  prfOutputHex: string
}

export type VerifiedIdentity =
  | VerifiedOauthIdentity
  | VerifiedEmailIdentity
  | VerifiedPasskeyIdentity

export interface CanonicalIdentitySubject {
  provider: IdentityProvider
  subject: string
}

export interface ProductJwtPayload {
  sub: string
  iss: string
  aud: string
  iat: number
  exp: number
  jti: string
  provider: IdentityProvider
  primaryProvider: IdentityProvider
}

export interface IdentityRecord {
  walletAddress: string
  primaryProvider: IdentityProvider
  primarySubject: string
  data: IdentityRecordData
  createdAt: string
  updatedAt: string
}

export interface IdentityRecordData {
  email?: string | null
  displayName?: string | null
}

export interface IdentityLinkRecord {
  aliasProvider: IdentityProvider
  aliasSubject: string
  primaryWalletAddress: string
  data: IdentityRecordData
  createdAt: string
}

export interface RefreshTokenRecord {
  tokenHash: string
  walletAddress: string
  createdAt: string
  expiresAt: string
  revokedAt: string | null
  userAgent: string | null
  ipHash: string | null
}

export type AuthMode = 'service' | 'user'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      authMode?: AuthMode
      userWalletAddress?: string
      userProvider?: IdentityProvider
      userPrimaryProvider?: IdentityProvider
      userJwtId?: string
    }
  }
}

export {}
