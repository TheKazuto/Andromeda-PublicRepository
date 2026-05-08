import { Router } from 'express'
import { z } from 'zod'
import { address as toAddress } from '@solana/kit'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { getPolicyAdapter } from '../adapters/SolanaAdapter.js'
import type { AppConfig } from '../../config.js'

/**
 * Quorum recovery via PDA staging (multi-tx flow):
 *
 *   POST /v1/recovery/quorum/session/open/challenge
 *     → returns the challenge for the primary to sign (open authorization).
 *   POST /v1/recovery/quorum/session/open
 *     → primary signature accepted; on-chain session PDA is created.
 *   POST /v1/recovery/quorum/session/contribute/challenge
 *     → returns the per-member challenge (single member, single tx).
 *   POST /v1/recovery/quorum/session/contribute
 *     → records one member's contribution on-chain.
 *   POST /v1/recovery/quorum/session/finalize
 *     → once threshold met, performs the CPI to Ika `approve_message`.
 *   POST /v1/recovery/quorum/session/close
 *     → after finalize/expiry, closes the session PDA and refunds rent.
 *   GET  /v1/recovery/quorum/session/:address
 *     → reads on-chain session state.
 */

// Audit C2 (Opção 4): every quorum endpoint requires init_authority_hash.
const openChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  messageDigestBase64: z.string(),
  metadataDigestBase64: z.string().default(''),
  userPubkeyBase64: z.string(),
  signatureScheme: z.number().int().min(0).max(6),
  amount: z.coerce.bigint().default(0n),
  destinationBase64: z.string().default(''),
  expiresAtSec: z.number().int().positive(),
})

const openSubmitSchema = openChallengeSchema.extend({
  primarySignatureBase64: z.string(),
  expectedSessionNonce: z.coerce.bigint(),
})

const contributeChallengeSchema = z.object({
  sessionAddress: z.string().min(32),
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  memberIndex: z.number().int().min(0).max(15),
})

const contributeSubmitSchema = contributeChallengeSchema.extend({
  memberSignatureBase64: z.string(),
  webauthnAuthDataBase64: z.string().optional(),
  webauthnClientDataJsonBase64: z.string().optional(),
})

const sessionAddressWithHashSchema = z.object({
  sessionAddress: z.string().min(32),
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
})

const sessionAddressSchema = z.object({
  sessionAddress: z.string().min(32),
})

function b64(s: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error(`${label} must be valid base64`)
  return Uint8Array.from(Buffer.from(s, 'base64'))
}

function b64Fixed(s: string, size: number, label: string): Uint8Array {
  if (s === '' && size === 32 && (label === 'metadataDigest' || label === 'destination')) {
    return new Uint8Array(32)
  }
  const out = b64(s, label)
  if (out.length !== size) throw new Error(`${label} must be ${size} bytes (got ${out.length})`)
  return out
}

export function buildQuorumRouter(_config: AppConfig): Router {
  const router = Router()

  // ── Session open ─────────────────────────────────────────

  router.post('/session/open/challenge', async (req, res) => {
    try {
      const input = openChallengeSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.prepareQuorumSessionOpen({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        messageDigest: b64Fixed(input.messageDigestBase64, 32, 'messageDigest'),
        metadataDigest: b64Fixed(input.metadataDigestBase64, 32, 'metadataDigest'),
        userPubkey: b64Fixed(input.userPubkeyBase64, 32, 'userPubkey'),
        signatureScheme: input.signatureScheme,
        amount: input.amount,
        destination: b64Fixed(input.destinationBase64, 32, 'destination'),
        expiresAt: new Date(input.expiresAtSec * 1000),
      })
      res.json(
        ok({
          challengeBase64: Buffer.from(result.challenge).toString('base64'),
          expectedSessionNonce: result.expectedSessionNonce.toString(),
          primaryScheme: result.primaryScheme,
          sessionAddress: result.sessionAddress,
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/open/challenge', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/session/open', async (req, res) => {
    try {
      const input = openSubmitSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.submitQuorumSessionOpen({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        messageDigest: b64Fixed(input.messageDigestBase64, 32, 'messageDigest'),
        metadataDigest: b64Fixed(input.metadataDigestBase64, 32, 'metadataDigest'),
        userPubkey: b64Fixed(input.userPubkeyBase64, 32, 'userPubkey'),
        signatureScheme: input.signatureScheme,
        amount: input.amount,
        destination: b64Fixed(input.destinationBase64, 32, 'destination'),
        expiresAt: new Date(input.expiresAtSec * 1000),
        primarySignature: b64(input.primarySignatureBase64, 'primarySignature'),
        expectedSessionNonce: input.expectedSessionNonce,
      })
      res.json(ok({ sessionAddress: result.sessionAddress, txSignature: result.txSignature }))
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/open', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  // ── Contribute ───────────────────────────────────────────

  router.post('/session/contribute/challenge', async (req, res) => {
    try {
      const input = contributeChallengeSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.prepareQuorumContribute({
        sessionAddress: toAddress(input.sessionAddress),
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        memberIndex: input.memberIndex,
      })
      res.json(
        ok({
          challengeBase64: Buffer.from(result.challenge).toString('base64'),
          memberScheme: result.memberSlot.scheme,
          memberIdentifierBase64: Buffer.from(result.memberSlot.identifier).toString('base64'),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/contribute/challenge', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/session/contribute', async (req, res) => {
    try {
      const input = contributeSubmitSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.submitQuorumContribute({
        sessionAddress: toAddress(input.sessionAddress),
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        memberIndex: input.memberIndex,
        memberSignature: b64(input.memberSignatureBase64, 'memberSignature'),
        ...(input.webauthnAuthDataBase64
          ? { webauthnAuthData: b64(input.webauthnAuthDataBase64, 'webauthnAuthData') }
          : {}),
        ...(input.webauthnClientDataJsonBase64
          ? {
              webauthnClientDataJson: b64(
                input.webauthnClientDataJsonBase64,
                'webauthnClientDataJson',
              ),
            }
          : {}),
      })
      res.json(
        ok({
          txSignature: result.txSignature,
          contributionsCount: result.contributionsCount,
          thresholdRequired: result.thresholdRequired,
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/contribute', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  // ── Finalize / Close ─────────────────────────────────────

  router.post('/session/finalize', async (req, res) => {
    try {
      const input = sessionAddressWithHashSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.submitQuorumFinalizeWithHash({
        sessionAddress: toAddress(input.sessionAddress),
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
      })
      res.json(
        ok({
          txSignature: result.txSignature,
          messageApprovalAddress: result.messageApprovalAddress,
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/finalize', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/session/close', async (req, res) => {
    try {
      const input = sessionAddressWithHashSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.submitQuorumCloseWithHash({
        sessionAddress: toAddress(input.sessionAddress),
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: b64Fixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
      })
      res.json(ok({ txSignature: result.txSignature }))
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/close', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  // ── Read state ───────────────────────────────────────────

  router.get('/session/:address', async (req, res) => {
    try {
      const address = req.params.address
      if (!address) {
        res.status(400).json(fail('Missing session address'))
        return
      }
      const adapter = getPolicyAdapter()
      const session = await adapter.readSession(toAddress(address))
      if (!session) {
        res.status(404).json(fail('Session not found'))
        return
      }
      res.json(
        ok({
          sessionAddress: session.sessionAddress,
          dwalletAddress: session.dwalletAddress,
          policyAddress: session.policyAddress,
          sessionNonce: session.sessionNonce.toString(),
          contributionsCount: session.contributionsCount,
          contributionsBitmap: session.contributionsBitmap,
          thresholdRequired: session.thresholdRequired,
          expiresAt: session.expiresAt.toISOString(),
          finalizedAt: session.finalizedAt?.toISOString() ?? null,
          membersSnapshot: session.membersSnapshot.map((m) => ({
            scheme: m.scheme,
            identifierBase64: Buffer.from(m.identifier).toString('base64'),
          })),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/quorum/session/get', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
