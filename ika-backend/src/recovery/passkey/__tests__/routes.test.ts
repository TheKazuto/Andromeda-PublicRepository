/**
 * HTTP smoke tests for `/v1/recovery/primary/passkey/*` (6 routes).
 *
 * Strategy mirrors the OIDC routes.test.ts:
 *   - Mock `recovery/adapters/solana/passkey.js` entirely. The Solana wire-up
 *     (precompiles, gas sponsor, rules-policy client) is covered by the
 *     adapter's own unit tests + the SBF passkey_challenge_fixtures suite.
 *     Here we only exercise the HTTP layer (Zod parse → base64 decode →
 *     adapter call → ok/fail).
 *   - Stub `SolanaAdapter.getSolanaCtx`.
 */

import express from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppConfig, PasskeyConfig } from '../../../config.js'

const adapter = vi.hoisted(() => ({
  preparePasskeySessionOpen: vi.fn(),
  submitPasskeySessionOpen: vi.fn(),
  preparePasskeyUse: vi.fn(),
  submitPasskeyUse: vi.fn(),
  submitPasskeySessionClose: vi.fn(),
  fetchPasskeySession: vi.fn(),
}))

vi.mock('../../adapters/solana/passkey.js', () => adapter)

vi.mock('../../adapters/SolanaAdapter.js', () => ({
  getSolanaCtx: () => ({ _stub: true }),
}))

const { buildPasskeyRecoveryRouter } = await import('../routes.js')

// ── fixtures ───────────────────────────────────────────────────────────

const ADDR = '11111111111111111111111111111111' // 32 zero bytes — valid base58 Solana address
const SESSION_ADDR = ADDR

const b64 = (n: number, fill = 0): string =>
  Buffer.from(new Uint8Array(n).fill(fill)).toString('base64')

const HASH32 = b64(32, 9)
const DIGEST32 = b64(32, 7)
const PUBKEY32 = b64(32, 0xbb)
const PUBKEY33 = b64(33, 0x02)
const SIG64 = b64(64, 0xaa)
const AUTH_DATA = b64(84, 0x55)
const CDJ = Buffer.from(
  JSON.stringify({ type: 'webauthn.get', challenge: 'aaaa', origin: 'https://app.example' }),
  'utf8',
).toString('base64')
const NOT_AFTER = 1_770_003_000n
const SESSION_NONCE = 0n
const USE_NONCE = 0n

function makeConfig(overrides: Partial<PasskeyConfig> = {}): AppConfig {
  const passkey: PasskeyConfig = {
    enabled: true,
    rpId: 'andromedainfra.pro',
    rpOrigin: 'https://app.andromedainfra.pro',
    challengeTtlSeconds: 120,
    saltMode: 'per_credential',
    sessionTtlSeconds: 600,
    ...overrides,
  }
  return { passkey } as AppConfig
}

function makeApp(): express.Express {
  const app = express()
  app.use(express.json())
  app.use(buildPasskeyRecoveryRouter(makeConfig()))
  return app
}

beforeEach(() => {
  for (const fn of Object.values(adapter)) fn.mockReset()
})

// ── /open/challenge ───────────────────────────────────────────────────

describe('POST /open/challenge', () => {
  it('happy path — returns challenge + clearSigning + rpId', async () => {
    adapter.preparePasskeySessionOpen.mockResolvedValueOnce({
      challenge: new Uint8Array(32).fill(1),
      humanMessage: 'Open passkey session for dWallet …',
      clearSigning: { version: 2, operation: 'passkey-session-open', fields: {} },
      expectedSessionNonce: SESSION_NONCE,
      sessionAddress: SESSION_ADDR,
    })
    const r = await request(makeApp())
      .post('/open/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        credentialPubkeyBase64: PUBKEY33,
        credentialIdHashBase64: HASH32,
        ephPkBase64: PUBKEY32,
        notAfterUnixTs: NOT_AFTER.toString(),
      })
    expect(r.status).toBe(200)
    expect(r.body.success).toBe(true)
    expect(r.body.data.challengeBase64).toBeDefined()
    expect(r.body.data.expectedSessionNonce).toBe('0')
    expect(r.body.data.sessionAddress).toBe(SESSION_ADDR)
    expect(r.body.data.rpId).toBe('andromedainfra.pro')
    expect(adapter.preparePasskeySessionOpen).toHaveBeenCalledOnce()
  })

  it('credentialPubkey wrong length → 500 sanitized (adapter not called)', async () => {
    const r = await request(makeApp())
      .post('/open/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        credentialPubkeyBase64: HASH32, // 32 bytes — should be 33
        credentialIdHashBase64: HASH32,
        ephPkBase64: PUBKEY32,
        notAfterUnixTs: NOT_AFTER.toString(),
      })
    expect(r.status).toBe(400)
    expect(adapter.preparePasskeySessionOpen).not.toHaveBeenCalled()
  })

  it('missing required field → 400', async () => {
    const r = await request(makeApp()).post('/open/challenge').send({})
    expect(r.status).toBe(400)
    expect(r.body.success).toBe(false)
  })

  it('adapter throws "policy primary is not WebAuthn" → 400 (client error)', async () => {
    adapter.preparePasskeySessionOpen.mockRejectedValueOnce(
      new Error('policy primary is not WebAuthn (scheme=0)'),
    )
    const r = await request(makeApp())
      .post('/open/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        credentialPubkeyBase64: PUBKEY33,
        credentialIdHashBase64: HASH32,
        ephPkBase64: PUBKEY32,
        notAfterUnixTs: NOT_AFTER.toString(),
      })
    expect(r.status).toBe(400)
  })
})

// ── /open ─────────────────────────────────────────────────────────────

describe('POST /open', () => {
  it('happy path — calls submitPasskeySessionOpen and returns txSignature', async () => {
    adapter.submitPasskeySessionOpen.mockResolvedValueOnce({
      txSignature: 'open-sig',
      sessionAddress: SESSION_ADDR,
    })
    const r = await request(makeApp())
      .post('/open')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        credentialPubkeyBase64: PUBKEY33,
        credentialIdHashBase64: HASH32,
        ephPkBase64: PUBKEY32,
        notAfterUnixTs: NOT_AFTER.toString(),
        webauthnAuthDataBase64: AUTH_DATA,
        webauthnClientDataJsonBase64: CDJ,
        webauthnSignatureBase64: SIG64,
        expectedSessionNonce: '0',
      })
    expect(r.status).toBe(200)
    expect(r.body.data.txSignature).toBe('open-sig')
    expect(adapter.submitPasskeySessionOpen).toHaveBeenCalledOnce()
  })

  it('webauthnAuthData over 192 bytes → 400 (does not call adapter)', async () => {
    const tooBig = b64(193, 0)
    const r = await request(makeApp())
      .post('/open')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        credentialPubkeyBase64: PUBKEY33,
        credentialIdHashBase64: HASH32,
        ephPkBase64: PUBKEY32,
        notAfterUnixTs: NOT_AFTER.toString(),
        webauthnAuthDataBase64: tooBig,
        webauthnClientDataJsonBase64: CDJ,
        webauthnSignatureBase64: SIG64,
        expectedSessionNonce: '0',
      })
    expect(r.status).toBe(400)
    expect(adapter.submitPasskeySessionOpen).not.toHaveBeenCalled()
  })
})

// ── /use/challenge ────────────────────────────────────────────────────

describe('POST /use/challenge', () => {
  it('happy path — returns challenge + expectedUseNonce + sessionExpiresAt', async () => {
    adapter.preparePasskeyUse.mockResolvedValueOnce({
      challenge: new Uint8Array(32).fill(2),
      humanMessage: 'Authorize passkey session …',
      clearSigning: { version: 2, operation: 'passkey-primary-use', fields: {} },
      expectedUseNonce: USE_NONCE,
      sessionExpiresAt: 1_770_001_100,
    })
    const r = await request(makeApp())
      .post('/use/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        sessionAddress: SESSION_ADDR,
        messageDigestBase64: DIGEST32,
        metadataDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32,
        signatureScheme: 0,
      })
    expect(r.status).toBe(200)
    expect(r.body.data.expectedUseNonce).toBe('0')
    expect(r.body.data.sessionExpiresAt).toBe(1_770_001_100)
  })

  it('adapter throws "session expired" → 400', async () => {
    adapter.preparePasskeyUse.mockRejectedValueOnce(new Error('Passkey session expired'))
    const r = await request(makeApp())
      .post('/use/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        sessionAddress: SESSION_ADDR,
        messageDigestBase64: DIGEST32,
        metadataDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32,
        signatureScheme: 0,
      })
    expect(r.status).toBe(400)
  })
})

// ── /use/submit ───────────────────────────────────────────────────────

describe('POST /use/submit', () => {
  it('happy path', async () => {
    adapter.submitPasskeyUse.mockResolvedValueOnce({
      txSignature: 'use-sig',
      messageApprovalAddress: ADDR,
    })
    const r = await request(makeApp())
      .post('/use/submit')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        sessionAddress: SESSION_ADDR,
        messageDigestBase64: DIGEST32,
        metadataDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32,
        signatureScheme: 0,
        ephSignatureBase64: SIG64,
        expectedUseNonce: '0',
      })
    expect(r.status).toBe(200)
    expect(r.body.data.txSignature).toBe('use-sig')
  })
})

// ── /close ────────────────────────────────────────────────────────────

describe('POST /close', () => {
  it('happy path', async () => {
    adapter.submitPasskeySessionClose.mockResolvedValueOnce({ txSignature: 'close-sig' })
    const r = await request(makeApp()).post('/close').send({
      dwalletAddress: ADDR,
      initAuthorityHashBase64: HASH32,
      sessionAddress: SESSION_ADDR,
    })
    expect(r.status).toBe(200)
    expect(r.body.data.txSignature).toBe('close-sig')
  })
})

// ── /capabilities ─────────────────────────────────────────────────────

describe('GET /capabilities', () => {
  it('echoes the configured passkey settings and on-chain bounds', async () => {
    const r = await request(makeApp()).get('/capabilities')
    expect(r.status).toBe(200)
    expect(r.body.data).toMatchObject({
      enabled: true,
      // Falls back to env defaults when the request carries no
      // X-Andromeda-Allowed-Origins header (Andromeda dashboard path).
      allowedOrigins: ['https://app.andromedainfra.pro'],
      saltMode: 'per_credential',
      challengeTtlSeconds: 120,
      sessionTtlSeconds: 600,
      onChainSessionTtlSeconds: 600,
      webauthnAuthDataMaxBytes: 192,
      webauthnClientDataJsonMaxBytes: 192,
    })
  })

  it('echoes the tenant allowlist forwarded by the gateway', async () => {
    const r = await request(makeApp())
      .get('/capabilities')
      .set('X-Andromeda-Allowed-Origins', 'https://app.cliente-a.com,https://wallet.cliente-a.com')
    expect(r.status).toBe(200)
    expect(r.body.data.allowedOrigins).toEqual([
      'https://app.cliente-a.com',
      'https://wallet.cliente-a.com',
    ])
  })
})
