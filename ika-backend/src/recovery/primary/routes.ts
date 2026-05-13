import { Router } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { getPolicyAdapter } from '../adapters/SolanaAdapter.js'
import { address as toAddress } from '@solana/kit'

/**
 * Primary recovery is now challenge-based + gas-sponsored:
 *
 * 1. POST /v1/recovery/primary/challenge
 *    → returns the 32-byte challenge for the primary credential to sign,
 *      plus the on-chain `expectedNonce` and `primaryScheme` (so the gateway
 *      knows what wallet to ask for).
 *
 * 2. POST /v1/recovery/primary/submit
 *    → accepts the off-chain signature; the backend builds the precompile +
 *      main ix, signs the Solana tx as gas sponsor, and returns
 *      `{ txSignature, messageApprovalAddress }`.
 */

// Audit C2 (Opção 4): both endpoints require init_authority_hash to address
// the right policy PDA.
const challengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  messageDigestBase64: z.string(),
  metadataDigestBase64: z.string().default(''),
  userPubkeyBase64: z.string(),
  signatureScheme: z.number().int().min(0).max(6),
})

const submitSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  messageDigestBase64: z.string(),
  metadataDigestBase64: z.string().default(''),
  userPubkeyBase64: z.string(),
  signatureScheme: z.number().int().min(0).max(6),
  primarySignatureBase64: z.string(),
  expectedNonce: z.coerce.bigint(),
})

function decodeBase64ToFixed(input: string, size: number, label: string): Uint8Array {
  if (input === '' && size === 32 && (label === 'metadataDigest' || label === 'metadata_digest')) {
    return new Uint8Array(32)
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new Error(`${label} must be valid base64`)
  }
  const buf = Buffer.from(input, 'base64')
  if (buf.length !== size) {
    throw new Error(`${label} must be ${size} bytes (got ${buf.length})`)
  }
  return Uint8Array.from(buf)
}

function decodeBase64(input: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new Error(`${label} must be valid base64`)
  }
  return Uint8Array.from(Buffer.from(input, 'base64'))
}

export function buildPrimaryRouter(): Router {
  const router = Router()

  router.post('/challenge', async (req, res) => {
    try {
      const input = challengeSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.prepareRecoverAsPrimary({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: decodeBase64ToFixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        messageDigest: decodeBase64ToFixed(input.messageDigestBase64, 32, 'messageDigest'),
        metadataDigest: decodeBase64ToFixed(input.metadataDigestBase64, 32, 'metadataDigest'),
        userPubkey: decodeBase64ToFixed(input.userPubkeyBase64, 32, 'userPubkey'),
        signatureScheme: input.signatureScheme,
      })
      res.json(
        ok({
          challengeBase64: Buffer.from(result.challenge).toString('base64'),
          expectedNonce: result.expectedNonce.toString(),
          primaryScheme: result.primaryScheme,
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/primary/challenge', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/submit', async (req, res) => {
    try {
      const input = submitSchema.parse(req.body)
      const adapter = getPolicyAdapter()
      const result = await adapter.submitRecoverAsPrimary({
        dwalletAddress: toAddress(input.dwalletAddress),
        initAuthorityHash: decodeBase64ToFixed(input.initAuthorityHashBase64, 32, 'initAuthorityHash'),
        messageDigest: decodeBase64ToFixed(input.messageDigestBase64, 32, 'messageDigest'),
        metadataDigest: decodeBase64ToFixed(input.metadataDigestBase64, 32, 'metadataDigest'),
        userPubkey: decodeBase64ToFixed(input.userPubkeyBase64, 32, 'userPubkey'),
        signatureScheme: input.signatureScheme,
        primarySignature: decodeBase64(input.primarySignatureBase64, 'primarySignature'),
        expectedNonce: input.expectedNonce,
      })
      res.json(
        ok({
          txSignature: result.txSignature,
          messageApprovalAddress: result.messageApprovalAddress,
        }),
      )
    } catch (err) {
      const safe = sanitizeError('recovery/primary/submit', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
