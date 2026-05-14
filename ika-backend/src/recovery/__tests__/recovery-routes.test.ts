import { describe, it, expect, vi, beforeEach } from 'vitest'
import express from 'express'
import request from 'supertest'

// Mock the policy adapter singleton — these route tests cover the HTTP wiring
// (Zod parse → base64 decode → adapter call → ok()/fail()), not the on-chain
// adapter itself (its byte-layout helpers are tested in solana/internal.test.ts).
const adapter = vi.hoisted(() => ({
  prepareRecoverAsPrimary: vi.fn(),
  submitRecoverAsPrimary: vi.fn(),
  prepareQuorumSessionOpen: vi.fn(),
  submitQuorumSessionOpen: vi.fn(),
  prepareQuorumContribute: vi.fn(),
  submitQuorumContribute: vi.fn(),
  submitQuorumFinalizeWithHash: vi.fn(),
  submitQuorumCloseWithHash: vi.fn(),
  readSession: vi.fn(),
}))
vi.mock('../adapters/SolanaAdapter.js', () => ({ getPolicyAdapter: () => adapter }))

const { buildPrimaryRouter } = await import('../primary/routes.js')
const { buildQuorumRouter } = await import('../quorum/routes.js')

const app = express()
app.use(express.json())
app.use('/primary', buildPrimaryRouter())
// eslint-disable-next-line @typescript-eslint/no-explicit-any
app.use('/quorum', buildQuorumRouter({} as any))

const ADDR = '11111111111111111111111111111111' // valid 32-byte base58 Solana address
const b64of = (n: number, fill = 1): string => Buffer.from(new Uint8Array(n).fill(fill)).toString('base64')
const HASH32 = b64of(32, 9)
const DIGEST32 = b64of(32, 7)
const SIG64 = b64of(64, 0xaa)
const PUBKEY32 = b64of(32, 0xbb)

describe('recovery/primary routes', () => {
  beforeEach(() => {
    for (const fn of Object.values(adapter)) fn.mockReset()
  })

  it('POST /primary/challenge — happy path', async () => {
    adapter.prepareRecoverAsPrimary.mockResolvedValueOnce({
      challenge: new Uint8Array(32).fill(3),
      humanMessage: 'Recover dWallet ... for message ... metadata ... scheme 5 user ...',
      clearSigning: {
        version: 'rules-policy-clear-v1',
        operation: 'primary-recover',
        fields: { signatureScheme: 5, expectedNonce: '5' },
      },
      expectedNonce: 5n,
      primaryScheme: 0,
    })
    const res = await request(app)
      .post('/primary/challenge')
      .send({
        dwalletAddress: ADDR,
        initAuthorityHashBase64: HASH32,
        messageDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32,
        signatureScheme: 5,
      })
    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.expectedNonce).toBe('5')
    expect(res.body.data.primaryScheme).toBe(0)
    expect(res.body.data.humanMessage).toMatch(/^Recover dWallet /)
    expect(res.body.data.clearSigning.version).toBe('rules-policy-clear-v1')
    expect(res.body.data.clearSigning.operation).toBe('primary-recover')
    expect(adapter.prepareRecoverAsPrimary).toHaveBeenCalledOnce()
  })

  it('POST /primary/challenge — invalid base64 → 400', async () => {
    const res = await request(app)
      .post('/primary/challenge')
      .send({ dwalletAddress: ADDR, initAuthorityHashBase64: '!!!notb64!!!', messageDigestBase64: DIGEST32 })
    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
  })

  it('POST /primary/challenge — missing field → 400', async () => {
    const res = await request(app).post('/primary/challenge').send({ dwalletAddress: ADDR })
    expect(res.status).toBe(400)
  })

  it('POST /primary/submit — happy path', async () => {
    adapter.submitRecoverAsPrimary.mockResolvedValueOnce({ txSignature: 'sigABC', messageApprovalAddress: ADDR })
    const res = await request(app)
      .post('/primary/submit')
      .send({
        dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, messageDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32, signatureScheme: 5, primarySignatureBase64: SIG64, expectedNonce: '7',
      })
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('sigABC')
    expect(adapter.submitRecoverAsPrimary).toHaveBeenCalledOnce()
    expect((adapter.submitRecoverAsPrimary.mock.calls[0]![0] as { expectedNonce: bigint }).expectedNonce).toBe(7n)
  })

  it('POST /primary/submit — adapter error is sanitized → 400', async () => {
    adapter.submitRecoverAsPrimary.mockRejectedValueOnce(new Error('Primary recover nonce mismatch: expected 8, got 7'))
    const res = await request(app)
      .post('/primary/submit')
      .send({
        dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, messageDigestBase64: DIGEST32,
        userPubkeyBase64: PUBKEY32, signatureScheme: 5, primarySignatureBase64: SIG64, expectedNonce: '7',
      })
    expect(res.status).toBe(400)
    expect(res.body.success).toBe(false)
    // not an allowlisted message → falls back to "Internal server error", with a trace id
    expect(typeof res.body.error).toBe('string')
  })
})

describe('recovery/quorum routes', () => {
  beforeEach(() => {
    for (const fn of Object.values(adapter)) fn.mockReset()
  })

  it('POST /quorum/session/open/challenge — happy path', async () => {
    adapter.prepareQuorumSessionOpen.mockResolvedValueOnce({
      challenge: new Uint8Array(32),
      humanMessage: 'Open quorum session for dWallet ...',
      clearSigning: { version: 'rules-policy-clear-v1', operation: 'quorum-session-open', fields: {} },
      expectedSessionNonce: 1n,
      primaryScheme: 1,
      sessionAddress: ADDR,
    })
    const res = await request(app)
      .post('/quorum/session/open/challenge')
      .send({ dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, messageDigestBase64: DIGEST32, userPubkeyBase64: PUBKEY32, signatureScheme: 0, expiresAtSec: 1_900_000_000 })
    expect(res.status).toBe(200)
    expect(res.body.data.sessionAddress).toBe(ADDR)
    expect(res.body.data.expectedSessionNonce).toBe('1')
    expect(res.body.data.humanMessage).toMatch(/^Open quorum session /)
    expect(res.body.data.clearSigning.operation).toBe('quorum-session-open')
  })

  it('POST /quorum/session/open — happy path', async () => {
    adapter.submitQuorumSessionOpen.mockResolvedValueOnce({ sessionAddress: ADDR, txSignature: 'open-sig' })
    const res = await request(app)
      .post('/quorum/session/open')
      .send({ dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, messageDigestBase64: DIGEST32, userPubkeyBase64: PUBKEY32, signatureScheme: 0, expiresAtSec: 1_900_000_000, primarySignatureBase64: SIG64, expectedSessionNonce: '1' })
    expect(res.status).toBe(200)
    expect(res.body.data.txSignature).toBe('open-sig')
  })

  it('POST /quorum/session/contribute/challenge — happy path', async () => {
    adapter.prepareQuorumContribute.mockResolvedValueOnce({
      challenge: new Uint8Array(32),
      humanMessage: 'Contribute to quorum session ...',
      clearSigning: { version: 'rules-policy-clear-v1', operation: 'quorum-contribute', fields: {} },
      memberSlot: { scheme: 0, identifier: new Uint8Array(32).fill(2) },
    })
    const res = await request(app)
      .post('/quorum/session/contribute/challenge')
      .send({ sessionAddress: ADDR, dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, memberIndex: 0 })
    expect(res.status).toBe(200)
    expect(res.body.data.memberScheme).toBe(0)
    expect(res.body.data.memberIdentifierBase64).toBe(b64of(32, 2))
    expect(res.body.data.humanMessage).toMatch(/^Contribute to quorum session/)
    expect(res.body.data.clearSigning.operation).toBe('quorum-contribute')
  })

  it('POST /quorum/session/contribute — happy path (member out of range surfaces as 400)', async () => {
    adapter.submitQuorumContribute.mockResolvedValueOnce({ txSignature: 'c-sig', contributionsCount: 2, thresholdRequired: 3 })
    const ok = await request(app)
      .post('/quorum/session/contribute')
      .send({ sessionAddress: ADDR, dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, memberIndex: 1, memberSignatureBase64: SIG64 })
    expect(ok.status).toBe(200)
    expect(ok.body.data.contributionsCount).toBe(2)

    adapter.submitQuorumContribute.mockRejectedValueOnce(new Error('memberIndex out of range for session snapshot'))
    const bad = await request(app)
      .post('/quorum/session/contribute')
      .send({ sessionAddress: ADDR, dwalletAddress: ADDR, initAuthorityHashBase64: HASH32, memberIndex: 1, memberSignatureBase64: SIG64 })
    expect(bad.status).toBe(400)
  })

  it('POST /quorum/session/finalize and /close — happy paths', async () => {
    adapter.submitQuorumFinalizeWithHash.mockResolvedValueOnce({ txSignature: 'fin-sig', messageApprovalAddress: ADDR })
    const fin = await request(app).post('/quorum/session/finalize').send({ sessionAddress: ADDR, dwalletAddress: ADDR, initAuthorityHashBase64: HASH32 })
    expect(fin.status).toBe(200)
    expect(fin.body.data.txSignature).toBe('fin-sig')

    adapter.submitQuorumCloseWithHash.mockResolvedValueOnce({ txSignature: 'close-sig' })
    const close = await request(app).post('/quorum/session/close').send({ sessionAddress: ADDR, dwalletAddress: ADDR, initAuthorityHashBase64: HASH32 })
    expect(close.status).toBe(200)
    expect(close.body.data.txSignature).toBe('close-sig')
  })

  it('GET /quorum/session/:address — 200 with state, 404 when missing', async () => {
    adapter.readSession.mockResolvedValueOnce({
      sessionAddress: ADDR, dwalletAddress: ADDR, policyAddress: ADDR, sessionNonce: 1n,
      messageDigest: new Uint8Array(32), metadataDigest: new Uint8Array(32), amount: 0n, destination: new Uint8Array(32),
      membersSnapshot: [{ scheme: 0, identifier: new Uint8Array(32).fill(4) }], thresholdRequired: 2,
      contributionsCount: 1, contributionsBitmap: 1, expiresAt: new Date('2026-01-01T00:00:00Z'), finalizedAt: null,
    })
    const res = await request(app).get(`/quorum/session/${ADDR}`)
    expect(res.status).toBe(200)
    expect(res.body.data.thresholdRequired).toBe(2)
    expect(res.body.data.membersSnapshot[0].identifierBase64).toBe(b64of(32, 4))
    expect(res.body.data.finalizedAt).toBeNull()

    adapter.readSession.mockResolvedValueOnce(null)
    const miss = await request(app).get(`/quorum/session/${ADDR}`)
    expect(miss.status).toBe(404)
  })
})
