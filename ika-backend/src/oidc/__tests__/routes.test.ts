/**
 * E2E HTTP tests for the public OIDC pre-step routes:
 *   POST /v1/oidc/nonce
 *   POST /v1/oidc/validate
 *
 * Strategy:
 *   - `/nonce` is pure crypto — exercise the real implementation.
 *   - `/validate` calls `verifyIdToken` (which talks to a remote JWKS over the
 *     network). We mock `../verify.js` so each test drives the route through a
 *     specific verifier outcome (success / IdTokenError / unexpected throw)
 *     without spinning up any HTTP/JWKS infrastructure.
 *   - `IdTokenError` and `MAX_ID_TOKEN_LEN` come from the real module so the
 *     `instanceof` check inside the route still passes.
 */

import express from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { OidcConfig } from '../../config.js'

const verifyMock = vi.hoisted(() => vi.fn())

vi.mock('../verify.js', async () => {
  const actual = await vi.importActual<typeof import('../verify.js')>('../verify.js')
  return {
    ...actual,
    verifyIdToken: verifyMock,
  }
})

const { buildOidcRouter } = await import('../routes.js')
const { deriveOidcNonce } = await import('../derive.js')

function makeConfig(overrides: Partial<OidcConfig> = {}): OidcConfig {
  return {
    enabled: true,
    googleEnabled: true,
    googleClientId: 'google-client-id',
    appleEnabled: false,
    appleClientId: undefined,
    allowedAudiences: ['andromeda-broker-devnet'],
    jwkRegistryAddress: '11111111111111111111111111111111',
    verifierVersion: 1,
    logSubjectHmacSecret: 'test-secret-min-32-bytes-aaaaaaaaaaaaaa',
    ...overrides,
  }
}

function makeApp(config: OidcConfig = makeConfig()): express.Express {
  const app = express()
  app.use(express.json())
  app.use(buildOidcRouter(config))
  return app
}

const b64 = (n: number, fill = 0): string =>
  Buffer.from(new Uint8Array(n).fill(fill)).toString('base64')

const EPH_PK_B64 = b64(32, 7)

describe('oidc routes — refuses to build without HMAC secret', () => {
  it('throws when logSubjectHmacSecret is missing', () => {
    expect(() => buildOidcRouter(makeConfig({ logSubjectHmacSecret: undefined }))).toThrow(
      /logSubjectHmacSecret/,
    )
  })
})

describe('POST /v1/oidc/nonce', () => {
  it('returns a 43-char base64url nonce + notAfter + randomness (default not_after)', async () => {
    const app = makeApp()
    const before = Math.floor(Date.now() / 1000)
    const res = await request(app).post('/nonce').send({ ephPkBase64: EPH_PK_B64 })
    const after = Math.floor(Date.now() / 1000)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.oidcNonce).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(res.body.data.notAfterUnixTs).toBeGreaterThan(before + 500)
    expect(res.body.data.notAfterUnixTs).toBeLessThanOrEqual(after + 540)
    expect(typeof res.body.data.nonceRandomnessBase64).toBe('string')
    const rand = Buffer.from(res.body.data.nonceRandomnessBase64, 'base64')
    expect(rand.length).toBe(32)
  })

  it('respects an explicit notAfterUnixTs within the allowed window', async () => {
    const app = makeApp()
    const target = Math.floor(Date.now() / 1000) + 1200
    const res = await request(app)
      .post('/nonce')
      .send({ ephPkBase64: EPH_PK_B64, notAfterUnixTs: target })

    expect(res.status).toBe(200)
    expect(res.body.data.notAfterUnixTs).toBe(target)
    // Re-deriving with the same inputs must match the response — sanity check
    // that the route uses the same canonical derivation as the client would.
    const rand = Uint8Array.from(Buffer.from(res.body.data.nonceRandomnessBase64, 'base64'))
    const ephPk = Uint8Array.from(Buffer.from(EPH_PK_B64, 'base64'))
    expect(deriveOidcNonce(ephPk, BigInt(target), rand)).toBe(res.body.data.oidcNonce)
  })

  it('rejects notAfter in the past', async () => {
    const app = makeApp()
    const past = Math.floor(Date.now() / 1000) - 60
    const res = await request(app)
      .post('/nonce')
      .send({ ephPkBase64: EPH_PK_B64, notAfterUnixTs: past })
    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
  })

  it('rejects notAfter past the 1h ceiling', async () => {
    const app = makeApp()
    const far = Math.floor(Date.now() / 1000) + 7200
    const res = await request(app)
      .post('/nonce')
      .send({ ephPkBase64: EPH_PK_B64, notAfterUnixTs: far })
    expect(res.status).toBe(400)
  })

  it('rejects ephPk that is not 32 bytes', async () => {
    const app = makeApp()
    const res = await request(app).post('/nonce').send({ ephPkBase64: b64(31, 5) })
    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
  })

  it('rejects ephPk that is not valid base64', async () => {
    const app = makeApp()
    const res = await request(app).post('/nonce').send({ ephPkBase64: '!!!notb64!!!' })
    expect(res.status).toBe(400)
  })

  it('rejects missing ephPk field', async () => {
    const app = makeApp()
    const res = await request(app).post('/nonce').send({})
    expect(res.status).toBe(400)
  })
})

describe('POST /v1/oidc/validate', () => {
  beforeEach(() => {
    verifyMock.mockReset()
  })

  const NONCE = 'pAqtrYL_Am8SKcwcG9vvIU6k4VoVNsC7V_i2a2cWuaU'
  const HAPPY_CLAIMS = {
    provider: 'google' as const,
    iss: 'https://accounts.google.com',
    aud: 'andromeda-broker-devnet',
    sub: '107492837465019283746',
    nonce: NONCE,
    kid: 'k1',
    iat: 1_770_000_000,
    exp: 1_770_003_600,
  }

  it('happy path — returns derived public identifiers, never raw sub/JWT', async () => {
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: 'h.p.s' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.valid).toBe(true)
    expect(res.body.data.provider).toBe('google')
    expect(typeof res.body.data.addrSeed).toBe('string')
    expect(Buffer.from(res.body.data.addrSeed, 'base64').length).toBe(32)
    expect(Buffer.from(res.body.data.issuerHash, 'base64').length).toBe(32)
    expect(Buffer.from(res.body.data.audienceHash, 'base64').length).toBe(32)
    expect(Buffer.from(res.body.data.subjectHash, 'base64').length).toBe(32)
    expect(res.body.data.expiresAt).toBe(HAPPY_CLAIMS.exp)
    // No raw identifiers leak.
    expect(JSON.stringify(res.body)).not.toContain(HAPPY_CLAIMS.sub)
    expect(JSON.stringify(res.body)).not.toContain('h.p.s')
  })

  it('IdTokenError (bad signature) → 200 + valid:false (no enumeration)', async () => {
    const { IdTokenError } = await import('../verify.js')
    verifyMock.mockRejectedValueOnce(new IdTokenError('bad_signature'))
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: 'h.p.s' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data).toEqual({ valid: false })
    // The reason stays server-side — never surfaced.
    expect(JSON.stringify(res.body)).not.toContain('bad_signature')
  })

  it('IdTokenError (audience_not_allowed) → 200 + valid:false', async () => {
    const { IdTokenError } = await import('../verify.js')
    verifyMock.mockRejectedValueOnce(new IdTokenError('audience_not_allowed'))
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: 'h.p.s' })

    expect(res.status).toBe(200)
    expect(res.body.data).toEqual({ valid: false })
  })

  it('IdTokenError (expired) → 200 + valid:false', async () => {
    const { IdTokenError } = await import('../verify.js')
    verifyMock.mockRejectedValueOnce(new IdTokenError('expired'))
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: 'h.p.s' })

    expect(res.status).toBe(200)
    expect(res.body.data).toEqual({ valid: false })
  })

  it('unexpected throw → 500 sanitized + traceId', async () => {
    verifyMock.mockRejectedValueOnce(new Error('upstream JWKS unreachable'))
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: 'h.p.s' })

    expect(res.status).toBe(500)
    expect(res.body.success).toBe(false)
    // sanitizeError must replace internal detail with the canonical message.
    expect(res.body.error).not.toContain('JWKS')
  })

  it('rejects missing idToken (Zod)', async () => {
    const app = makeApp()
    const res = await request(app).post('/validate').send({})
    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
    expect(verifyMock).not.toHaveBeenCalled()
  })

  it('rejects empty idToken', async () => {
    const app = makeApp()
    const res = await request(app).post('/validate').send({ idToken: '' })
    expect(res.status).toBe(400)
  })

  it('rejects idToken longer than MAX_ID_TOKEN_LEN', async () => {
    const { MAX_ID_TOKEN_LEN } = await import('../verify.js')
    const app = makeApp()
    const res = await request(app)
      .post('/validate')
      .send({ idToken: 'a'.repeat(MAX_ID_TOKEN_LEN + 1) })
    expect(res.status).toBe(400)
    expect(verifyMock).not.toHaveBeenCalled()
  })
})
