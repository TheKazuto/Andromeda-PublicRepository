import { describe, it, expect, vi, beforeEach } from 'vitest'

const JWT_CFG = { secret: 'a'.repeat(48), ttlSeconds: 3600, issuer: 'andromeda', audience: 'andromeda-app', refreshTtlDays: 30 }
vi.mock('../config.js', () => ({ getIdentityConfig: () => ({ jwt: JWT_CFG }) }))

const { issueProductJwt, verifyProductJwt, generateRefreshToken, InvalidProductJwtError, _resetJwtSecretCache, hashRefreshTokenValue } =
  await import('../jwt.js')

describe('identity/jwt — product JWT', () => {
  beforeEach(() => _resetJwtSecretCache())

  it('round-trips: a freshly issued JWT verifies with the expected claims', async () => {
    const issued = await issueProductJwt({ walletAddress: 'wallet-abc', provider: 'oauth-google', primaryProvider: 'oauth-google' })
    expect(issued.token.split('.')).toHaveLength(3)
    const payload = await verifyProductJwt(issued.token)
    expect(payload.sub).toBe('wallet-abc')
    expect(payload.provider).toBe('oauth-google')
    expect(payload.primaryProvider).toBe('oauth-google')
    expect(payload.iss).toBe('andromeda')
    expect(payload.aud).toBe('andromeda-app')
    expect(payload.jti).toBe(issued.jwtId)
  })

  it('rejects a token with a tampered signature', async () => {
    const { token } = await issueProductJwt({ walletAddress: 'w', provider: 'email', primaryProvider: 'email' })
    const [h, p, s] = token.split('.')
    const tampered = `${h}.${p}.${s!.slice(0, -2)}xx`
    await expect(verifyProductJwt(tampered)).rejects.toBeInstanceOf(InvalidProductJwtError)
  })

  it('rejects a token signed with a different secret', async () => {
    const { token } = await issueProductJwt({ walletAddress: 'w', provider: 'email', primaryProvider: 'email' })
    JWT_CFG.secret = 'b'.repeat(48)
    _resetJwtSecretCache()
    try {
      await expect(verifyProductJwt(token)).rejects.toBeInstanceOf(InvalidProductJwtError)
    } finally {
      JWT_CFG.secret = 'a'.repeat(48)
      _resetJwtSecretCache()
    }
  })

  it('rejects garbage', async () => {
    await expect(verifyProductJwt('not-a-jwt')).rejects.toBeInstanceOf(InvalidProductJwtError)
    await expect(verifyProductJwt('')).rejects.toBeInstanceOf(InvalidProductJwtError)
  })
})

describe('identity/jwt — refresh tokens', () => {
  it('generateRefreshToken yields a token whose hash matches hashRefreshTokenValue', () => {
    const t = generateRefreshToken()
    expect(t.token).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(t.tokenHash).toBe(hashRefreshTokenValue(t.token))
    expect(t.expiresAt.getTime()).toBeGreaterThan(Date.now())
  })

  it('produces a fresh token each call', () => {
    expect(generateRefreshToken().token).not.toBe(generateRefreshToken().token)
  })
})
