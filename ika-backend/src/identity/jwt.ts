// Identity layer — product JWT + refresh tokens.
// HS256 with IKA_IDENTITY_JWT_SECRET. Short-lived access + rotating refresh.

import { randomBytes, randomUUID } from 'node:crypto'
import { jwtVerify, SignJWT } from 'jose'
import { getIdentityConfig } from './config.js'
import {
  consumeRefreshTokenForRotation,
  createRefreshToken,
  hashRefreshTokenValue,
  withIdentityTransaction,
} from './store.js'

export { hashRefreshTokenValue } from './store.js'
import type { IdentityProvider, ProductJwtPayload } from './types.js'

let cachedSecretKey: Uint8Array | null = null
let cachedSecretSource: string | null = null

function getSecretKey(): Uint8Array {
  const { secret } = getIdentityConfig().jwt
  if (!secret) throw new Error('IKA_IDENTITY_JWT_SECRET is not configured.')
  if (cachedSecretSource !== secret || cachedSecretKey === null) {
    cachedSecretKey = new TextEncoder().encode(secret)
    cachedSecretSource = secret
  }
  return cachedSecretKey
}

export interface IssueProductJwtInput {
  walletAddress: string
  provider: IdentityProvider
  primaryProvider: IdentityProvider
}

export interface IssuedProductJwt {
  token: string
  expiresAt: string
  jwtId: string
}

export async function issueProductJwt(input: IssueProductJwtInput): Promise<IssuedProductJwt> {
  const config = getIdentityConfig()
  const key = getSecretKey()
  const jti = randomUUID()
  const issuedAt = Math.floor(Date.now() / 1000)
  const expiresAt = issuedAt + config.jwt.ttlSeconds
  const token = await new SignJWT({
    provider: input.provider,
    primaryProvider: input.primaryProvider,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(input.walletAddress)
    .setIssuer(config.jwt.issuer)
    .setAudience(config.jwt.audience)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .setJti(jti)
    .sign(key)
  return { token, expiresAt: new Date(expiresAt * 1000).toISOString(), jwtId: jti }
}

export class InvalidProductJwtError extends Error {
  constructor(message = 'Invalid product JWT') {
    super(message)
    this.name = 'InvalidProductJwtError'
  }
}

export async function verifyProductJwt(token: string): Promise<ProductJwtPayload> {
  const config = getIdentityConfig()
  const key = getSecretKey()
  try {
    const { payload } = await jwtVerify(token, key, {
      algorithms: ['HS256'],
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      clockTolerance: 5,
    })

    const provider = payload.provider
    const primaryProvider = payload.primaryProvider

    if (typeof payload.sub !== 'string' || payload.sub.length === 0)
      throw new InvalidProductJwtError('JWT missing subject')
    if (typeof payload.jti !== 'string' || payload.jti.length === 0)
      throw new InvalidProductJwtError('JWT missing jti')
    if (typeof provider !== 'string' || typeof primaryProvider !== 'string')
      throw new InvalidProductJwtError('JWT missing provider claims')
    if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number')
      throw new InvalidProductJwtError('JWT missing iat/exp')

    return {
      sub: payload.sub,
      iss: config.jwt.issuer,
      aud: config.jwt.audience,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
      provider: provider as IdentityProvider,
      primaryProvider: primaryProvider as IdentityProvider,
    }
  } catch (err) {
    if (err instanceof InvalidProductJwtError) throw err
    throw new InvalidProductJwtError()
  }
}

export interface IssuedRefreshToken {
  token: string
  tokenHash: string
  expiresAt: Date
}

export function generateRefreshToken(): IssuedRefreshToken {
  const config = getIdentityConfig()
  const token = randomBytes(32).toString('base64url')
  const tokenHash = hashRefreshTokenValue(token)
  const expiresAt = new Date(Date.now() + config.jwt.refreshTtlDays * 86_400 * 1000)
  return { token, tokenHash, expiresAt }
}

export interface PersistRefreshTokenInput {
  walletAddress: string
  userAgent?: string | null
  ipHash?: string | null
}

export interface PersistedRefreshToken extends IssuedRefreshToken {
  walletAddress: string
}

export async function persistRefreshToken(
  input: PersistRefreshTokenInput,
): Promise<PersistedRefreshToken> {
  const generated = generateRefreshToken()
  await createRefreshToken({
    tokenHash: generated.tokenHash,
    walletAddress: input.walletAddress,
    expiresAt: generated.expiresAt,
    userAgent: input.userAgent ?? null,
    ipHash: input.ipHash ?? null,
  })
  return { ...generated, walletAddress: input.walletAddress }
}

export class InvalidRefreshTokenError extends Error {
  constructor(message = 'Invalid refresh token') {
    super(message)
    this.name = 'InvalidRefreshTokenError'
  }
}

export interface RotatedSession {
  walletAddress: string
  productJwt: IssuedProductJwt
  refreshToken: PersistedRefreshToken
}

export interface RotateRefreshTokenInput {
  refreshToken: string
  provider: IdentityProvider
  primaryProvider: IdentityProvider
  userAgent?: string | null
  ipHash?: string | null
}

export async function rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotatedSession> {
  const tokenHash = hashRefreshTokenValue(input.refreshToken)
  const generated = generateRefreshToken()

  // Atomic: consume the old token (gated UPDATE that fails if revoked or
  // expired) and insert the new one in the same transaction. Eliminates
  // the SELECT roundtrip and the race window of the previous flow.
  const walletAddress = await withIdentityTransaction(async (client) => {
    const consumed = await consumeRefreshTokenForRotation(tokenHash, client)
    if (!consumed) throw new InvalidRefreshTokenError()
    await createRefreshToken(
      {
        tokenHash: generated.tokenHash,
        walletAddress: consumed.walletAddress,
        expiresAt: generated.expiresAt,
        userAgent: input.userAgent ?? null,
        ipHash: input.ipHash ?? null,
      },
      client,
    )
    return consumed.walletAddress
  })

  const productJwt = await issueProductJwt({
    walletAddress,
    provider: input.provider,
    primaryProvider: input.primaryProvider,
  })

  return {
    walletAddress,
    productJwt,
    refreshToken: { ...generated, walletAddress },
  }
}

export function _resetJwtSecretCache(): void {
  cachedSecretKey = null
  cachedSecretSource = null
}
