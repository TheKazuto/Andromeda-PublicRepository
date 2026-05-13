/**
 * E2E HTTP tests for `/v1/recovery/primary/oidc/*` (7 routes).
 *
 *   stage / open/challenge / open / use/challenge / use/submit / close /
 *   staging/close
 *
 * Strategy:
 *   - Mock `recovery/adapters/solana/oidc.js` entirely. The wire-up between
 *     Solana RPC, gas sponsor, rules-policy client, message-approval PDA and
 *     Ika CPI is covered in unit/SBF tests; here we exercise the HTTP layer
 *     (Zod parse → base64 decode → derive flow → adapter call → ok/fail).
 *   - Mock `oidc/verify.js` so the route's server-side re-validation step
 *     returns deterministic claims. The pure `deriveOidcNonce` runs for real
 *     so the nonce-match guard inside `deriveFromStagedJwt` is exercised end
 *     to end.
 *   - Stub `SolanaAdapter.getSolanaCtx` to return an opaque sentinel object
 *     (mocked adapters never inspect it).
 */

import express from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppConfig, OidcConfig } from '../../../config.js'

// ── hoisted mocks ──────────────────────────────────────────────────────

const adapter = vi.hoisted(() => ({
  submitOidcJwtStage: vi.fn(),
  prepareOidcSessionOpen: vi.fn(),
  submitOidcSessionOpen: vi.fn(),
  prepareOidcUse: vi.fn(),
  submitOidcUse: vi.fn(),
  submitOidcSessionClose: vi.fn(),
  submitOidcJwtStagingClose: vi.fn(),
  fetchOidcStaging: vi.fn(),
  jwsSigningInputDigest: vi.fn(),
}))

const verifyMock = vi.hoisted(() => vi.fn())

vi.mock('../../adapters/solana/oidc.js', () => adapter)

vi.mock('../../../oidc/verify.js', async () => {
  const actual = await vi.importActual<typeof import('../../../oidc/verify.js')>(
    '../../../oidc/verify.js',
  )
  return {
    ...actual,
    verifyIdToken: verifyMock,
  }
})

vi.mock('../../adapters/SolanaAdapter.js', () => ({
  getSolanaCtx: () => ({ _stub: true }),
}))

const { buildOidcRecoveryRouter } = await import('../routes.js')
const { deriveOidcNonce } = await import('../../../oidc/derive.js')

// ── fixtures ───────────────────────────────────────────────────────────

// Real 32-byte base58 Solana addresses — the only base58 strings @solana/kit's
// `address()` accepts. We mock every adapter call, so all three can resolve to
// the same address; what we test is the HTTP wiring around them.
const ADDR = '11111111111111111111111111111111' // System Program (32 zero bytes)
const SESSION_ADDR = ADDR
const STAGING_ADDR = ADDR

const b64 = (n: number, fill = 0): string =>
  Buffer.from(new Uint8Array(n).fill(fill)).toString('base64')

const HASH32 = b64(32, 9)
const DIGEST32 = b64(32, 7)
const PUBKEY32 = b64(32, 0xbb)
const SIG64 = b64(64, 0xaa)
const EPH_PK = new Uint8Array(32).fill(7)
const EPH_PK_B64 = Buffer.from(EPH_PK).toString('base64')
const NONCE_RAND = new Uint8Array(32).fill(9)
const NONCE_RAND_B64 = Buffer.from(NONCE_RAND).toString('base64')
const NOT_AFTER = 1_770_003_000n

function makeConfig(overrides: Partial<OidcConfig> = {}): AppConfig {
  const oidc: OidcConfig = {
    enabled: true,
    googleEnabled: true,
    googleClientId: 'google-client-id',
    appleEnabled: false,
    appleClientId: undefined,
    allowedAudiences: ['andromeda-broker-devnet'],
    jwkRegistryAddress: ADDR,
    verifierVersion: 1,
    logSubjectHmacSecret: 'test-secret-hmac-aaaaaaaaaaaaaaaaa',
    ...overrides,
  }
  // The recovery router only reads `config.oidc`; cast to AppConfig.
  return { oidc } as AppConfig
}

function makeApp(): express.Express {
  const app = express()
  app.use(express.json())
  app.use(buildOidcRecoveryRouter(makeConfig()))
  return app
}

const HAPPY_CLAIMS = {
  provider: 'google' as const,
  iss: 'https://accounts.google.com',
  aud: 'andromeda-broker-devnet',
  sub: '107492837465019283746',
  // Precomputed by deriveOidcNonce(EPH_PK, NOT_AFTER, NONCE_RAND); matches the
  // golden vector in oidc/__tests__/derive.test.ts.
  nonce: deriveOidcNonce(EPH_PK, NOT_AFTER, NONCE_RAND),
  kid: 'k1',
  iat: 1_770_000_000,
  exp: 1_770_003_600, // > NOT_AFTER → passes the exp_before_not_after guard
}

function jwtBytesOf(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

beforeEach(() => {
  for (const fn of Object.values(adapter)) fn.mockReset()
  verifyMock.mockReset()
})

// ── /stage ────────────────────────────────────────────────────────────

describe('POST /stage', () => {
  it('happy path — validates JWT server-side then calls submitOidcJwtStage', async () => {
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    adapter.submitOidcJwtStage.mockResolvedValueOnce({
      txSignature: 'stage-sig',
      stagingAddress: STAGING_ADDR,
      stagingNonce: 3n,
    })
    const res = await request(makeApp()).post('/stage').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      idToken: 'h.p.s',
    })
    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.txSignature).toBe('stage-sig')
    expect(res.body.data.stagingNonce).toBe('3')
    expect(verifyMock).toHaveBeenCalledOnce()
    expect(adapter.submitOidcJwtStage).toHaveBeenCalledOnce()
  })

  it('IdTokenError → 400 "Invalid id_token" (does not call adapter)', async () => {
    const { IdTokenError } = await import('../../../oidc/verify.js')
    verifyMock.mockRejectedValueOnce(new IdTokenError('bad_signature'))
    const res = await request(makeApp()).post('/stage').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      idToken: 'h.p.s',
    })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Invalid id_token')
    expect(adapter.submitOidcJwtStage).not.toHaveBeenCalled()
  })

  it('id_token over MAX_ID_TOKEN_LEN → 400 (Zod, no JWT verify)', async () => {
    const { MAX_ID_TOKEN_LEN } = await import('../../../oidc/verify.js')
    const res = await request(makeApp()).post('/stage').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      idToken: 'a'.repeat(MAX_ID_TOKEN_LEN + 1),
    })
    expect(res.status).toBe(400)
    expect(verifyMock).not.toHaveBeenCalled()
  })

  it('invalid base64 initAuthorityHash → 500 sanitized (adapter not called)', async () => {
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    const res = await request(makeApp()).post('/stage').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: '!!!notb64!!!',
      idToken: 'h.p.s',
    })
    expect(res.status).toBe(500)
    expect(res.body.success).toBe(false)
    expect(res.body.traceId).toMatch(/^trc_/)
    expect(adapter.submitOidcJwtStage).not.toHaveBeenCalled()
  })

  it('adapter throws → 500 with traceId; raw message not leaked', async () => {
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    adapter.submitOidcJwtStage.mockRejectedValueOnce(new Error('rpc deadline exceeded'))
    const res = await request(makeApp()).post('/stage').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      idToken: 'h.p.s',
    })
    expect(res.status).toBe(500)
    expect(res.body.success).toBe(false)
    expect(res.body.error).not.toContain('rpc deadline')
    expect(res.body.traceId).toMatch(/^trc_/)
  })
})

// ── /open/challenge ───────────────────────────────────────────────────

describe('POST /open/challenge', () => {
  it('happy path — fetches staging, re-verifies JWT, returns challenge', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32).fill(1))
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    adapter.prepareOidcSessionOpen.mockResolvedValueOnce({
      challenge: new Uint8Array(32).fill(2),
      expectedSessionNonce: 4n,
      sessionAddress: SESSION_ADDR,
      jwkRegistryAddress: ADDR,
      jwkRegistryBump: 254,
      oidcVerifierVersion: 1,
    })

    const res = await request(makeApp()).post('/open/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      stagingAddress: STAGING_ADDR,
      ephPkBase64: EPH_PK_B64,
      notAfterUnixTs: NOT_AFTER.toString(),
      nonceRandomnessBase64: NONCE_RAND_B64,
    })
    expect(res.status).toBe(200)
    expect(res.body.data.challengeBase64).toBe(Buffer.from(new Uint8Array(32).fill(2)).toString('base64'))
    expect(res.body.data.expectedSessionNonce).toBe('4')
    expect(res.body.data.sessionAddress).toBe(SESSION_ADDR)
    expect(res.body.data.oidcVerifierVersion).toBe(1)
    expect(res.body.data.jwtExpiresAt).toBe(HAPPY_CLAIMS.exp)
    // addrSeed must be 32 base64 bytes
    expect(Buffer.from(res.body.data.addrSeedBase64, 'base64').length).toBe(32)
  })

  it('nonce mismatch (JWT claim ≠ derived nonce) → 400 Invalid id_token', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce({ ...HAPPY_CLAIMS, nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })

    const res = await request(makeApp()).post('/open/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      stagingAddress: STAGING_ADDR,
      ephPkBase64: EPH_PK_B64,
      notAfterUnixTs: NOT_AFTER.toString(),
      nonceRandomnessBase64: NONCE_RAND_B64,
    })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Invalid id_token')
    expect(adapter.prepareOidcSessionOpen).not.toHaveBeenCalled()
  })

  it('exp before notAfter → 400 Invalid id_token (no gas burned)', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce({ ...HAPPY_CLAIMS, exp: Number(NOT_AFTER) - 1 })

    const res = await request(makeApp()).post('/open/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      stagingAddress: STAGING_ADDR,
      ephPkBase64: EPH_PK_B64,
      notAfterUnixTs: NOT_AFTER.toString(),
      nonceRandomnessBase64: NONCE_RAND_B64,
    })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Invalid id_token')
    expect(adapter.prepareOidcSessionOpen).not.toHaveBeenCalled()
  })

  it('staged JWT empty / too long → 400 Invalid id_token', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: new Uint8Array(0) })
    const res = await request(makeApp()).post('/open/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      stagingAddress: STAGING_ADDR,
      ephPkBase64: EPH_PK_B64,
      notAfterUnixTs: NOT_AFTER.toString(),
      nonceRandomnessBase64: NONCE_RAND_B64,
    })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Invalid id_token')
  })

  it('missing required fields → 400', async () => {
    const res = await request(makeApp()).post('/open/challenge').send({ dwalletAddress: ADDR })
    expect(res.status).toBe(400)
    expect(adapter.fetchOidcStaging).not.toHaveBeenCalled()
  })

  it('invalid ephPk length → 500 sanitized', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    const res = await request(makeApp()).post('/open/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      stagingAddress: STAGING_ADDR,
      ephPkBase64: b64(31, 5),
      notAfterUnixTs: NOT_AFTER.toString(),
      nonceRandomnessBase64: NONCE_RAND_B64,
    })
    expect(res.status).toBe(500)
  })
})

// ── /open ─────────────────────────────────────────────────────────────

describe('POST /open', () => {
  function happySend(): Promise<request.Response> {
    return request(makeApp())
      .post('/open')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        stagingAddress: STAGING_ADDR,
        ephPkBase64: EPH_PK_B64,
        notAfterUnixTs: NOT_AFTER.toString(),
        nonceRandomnessBase64: NONCE_RAND_B64,
        ephSignatureBase64: SIG64,
        expectedSessionNonce: '4',
      })
  }

  it('happy path — submits transaction and returns session address', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    adapter.submitOidcSessionOpen.mockResolvedValueOnce({
      txSignature: 'open-sig',
      sessionAddress: SESSION_ADDR,
    })
    const res = await happySend()
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('open-sig')
    expect(res.body.data.sessionAddress).toBe(SESSION_ADDR)
    // The route must forward the verified hashes to the adapter.
    const args = adapter.submitOidcSessionOpen.mock.calls[0]![1] as {
      issuerHash: Uint8Array
      audienceHash: Uint8Array
      kidHash: Uint8Array
      expectedSessionNonce: bigint
    }
    expect(args.issuerHash.length).toBe(32)
    expect(args.audienceHash.length).toBe(32)
    expect(args.kidHash.length).toBe(32)
    expect(args.expectedSessionNonce).toBe(4n)
  })

  it('nonce mismatch surfaces before any tx submission', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce({
      ...HAPPY_CLAIMS,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    })
    const res = await happySend()
    expect(res.status).toBe(400)
    expect(adapter.submitOidcSessionOpen).not.toHaveBeenCalled()
  })

  it('adapter rejects (e.g. session_nonce mismatch) → 500 sanitized', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    adapter.submitOidcSessionOpen.mockRejectedValueOnce(new Error('OIDC session nonce mismatch: expected 5, got 4'))
    const res = await happySend()
    expect(res.status).toBe(500)
    expect(res.body.success).toBe(false)
    expect(res.body.traceId).toMatch(/^trc_/)
  })

  it('ephSignature wrong length → 500 sanitized', async () => {
    adapter.fetchOidcStaging.mockResolvedValueOnce({ jwt: jwtBytesOf('h.p.s') })
    adapter.jwsSigningInputDigest.mockReturnValueOnce(new Uint8Array(32))
    verifyMock.mockResolvedValueOnce(HAPPY_CLAIMS)
    const res = await request(makeApp())
      .post('/open')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        stagingAddress: STAGING_ADDR,
        ephPkBase64: EPH_PK_B64,
        notAfterUnixTs: NOT_AFTER.toString(),
        nonceRandomnessBase64: NONCE_RAND_B64,
        ephSignatureBase64: b64(63, 0xaa),
        expectedSessionNonce: '4',
      })
    expect(res.status).toBe(500)
    expect(adapter.submitOidcSessionOpen).not.toHaveBeenCalled()
  })

  it('missing fields → 400', async () => {
    const res = await request(makeApp()).post('/open').send({ dwalletAddress: ADDR })
    expect(res.status).toBe(400)
  })
})

// ── /use/challenge ────────────────────────────────────────────────────

describe('POST /use/challenge', () => {
  it('happy path — returns the per-use challenge', async () => {
    adapter.prepareOidcUse.mockResolvedValueOnce({
      challenge: new Uint8Array(32).fill(3),
      expectedUseNonce: 1n,
      sessionExpiresAt: 1_770_003_600,
    })
    const res = await request(makeApp()).post('/use/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
      messageDigestBase64: DIGEST32,
      userPubkeyBase64: PUBKEY32,
      signatureScheme: 0,
    })
    expect(res.status).toBe(200)
    expect(res.body.data.expectedUseNonce).toBe('1')
    expect(res.body.data.sessionExpiresAt).toBe(1_770_003_600)
    // metadataDigest is optional — route defaults it; the adapter must receive
    // a 32-byte zero buffer when omitted.
    const args = adapter.prepareOidcUse.mock.calls[0]![1] as { metadataDigest: Uint8Array }
    expect(args.metadataDigest.length).toBe(32)
    expect(Buffer.from(args.metadataDigest).every((b) => b === 0)).toBe(true)
  })

  it('adapter rejects (e.g. expired session) → 500 sanitized', async () => {
    adapter.prepareOidcUse.mockRejectedValueOnce(new Error('OIDC session expired'))
    const res = await request(makeApp()).post('/use/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
      messageDigestBase64: DIGEST32,
      userPubkeyBase64: PUBKEY32,
      signatureScheme: 0,
    })
    expect(res.status).toBe(500)
    expect(res.body.traceId).toMatch(/^trc_/)
  })

  it('signatureScheme out of range → 400', async () => {
    const res = await request(makeApp()).post('/use/challenge').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
      messageDigestBase64: DIGEST32,
      userPubkeyBase64: PUBKEY32,
      signatureScheme: 99,
    })
    expect(res.status).toBe(400)
  })
})

// ── /use/submit ───────────────────────────────────────────────────────

describe('POST /use/submit', () => {
  it('happy path — submits the recover_as_primary_oidc_session tx', async () => {
    adapter.submitOidcUse.mockResolvedValueOnce({
      txSignature: 'use-sig',
      messageApprovalAddress: ADDR,
    })
    const res = await request(makeApp()).post('/use/submit').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
      messageDigestBase64: DIGEST32,
      userPubkeyBase64: PUBKEY32,
      signatureScheme: 0,
      ephSignatureBase64: SIG64,
      expectedUseNonce: '2',
    })
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('use-sig')
    expect(res.body.data.messageApprovalAddress).toBe(ADDR)
    const args = adapter.submitOidcUse.mock.calls[0]![1] as { expectedUseNonce: bigint }
    expect(args.expectedUseNonce).toBe(2n)
  })

  it('adapter use-nonce mismatch → 500 sanitized', async () => {
    adapter.submitOidcUse.mockRejectedValueOnce(new Error('OIDC use nonce mismatch: expected 3, got 2'))
    const res = await request(makeApp()).post('/use/submit').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
      messageDigestBase64: DIGEST32,
      userPubkeyBase64: PUBKEY32,
      signatureScheme: 0,
      ephSignatureBase64: SIG64,
      expectedUseNonce: '2',
    })
    expect(res.status).toBe(500)
  })
})

// ── /close ────────────────────────────────────────────────────────────

describe('POST /close', () => {
  it('happy path', async () => {
    adapter.submitOidcSessionClose.mockResolvedValueOnce({ txSignature: 'close-sig' })
    const res = await request(makeApp()).post('/close').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
    })
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('close-sig')
  })

  it('adapter error → 500 sanitized', async () => {
    adapter.submitOidcSessionClose.mockRejectedValueOnce(new Error('account not closable yet'))
    const res = await request(makeApp()).post('/close').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
    })
    expect(res.status).toBe(500)
    expect(res.body.error).not.toContain('account not closable')
  })
})

// ── /staging/close ────────────────────────────────────────────────────

describe('POST /staging/close', () => {
  it('happy path', async () => {
    adapter.submitOidcJwtStagingClose.mockResolvedValueOnce({ txSignature: 'sc-sig' })
    const res = await request(makeApp()).post('/staging/close').send({
      stagingAddress: STAGING_ADDR,
    })
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('sc-sig')
  })

  it('missing stagingAddress → 400', async () => {
    const res = await request(makeApp()).post('/staging/close').send({})
    expect(res.status).toBe(400)
    expect(adapter.submitOidcJwtStagingClose).not.toHaveBeenCalled()
  })
})
