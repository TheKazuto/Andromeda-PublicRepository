/**
 * Login Social — gas-sponsored recovery routes (loginsocial.md §6.1, §10).
 *
 * Mounted at `/v1/recovery/primary/oidc/*` (under the recovery router's
 * `X-Api-Key` middleware). The user only signs the 32-byte `oidc-session-open`
 * / `oidc-primary-use` challenges off-chain with their ephemeral Ed25519 key;
 * the backend builds, signs (gas sponsor = fee payer) and submits the Solana
 * transactions via `solana/oidc.ts`. The `id_token` is re-validated server-side
 * (`jose` JWKS) before any gas is spent — never logged in clear.
 *
 *   POST /stage           → oidc_jwt_stage
 *   POST /open/challenge   → (read-only) challenge for the ephemeral key to sign
 *   POST /open            → oidc_session_open
 *   POST /use/challenge   → (read-only) per-use challenge
 *   POST /use/submit      → recover_as_primary_oidc_session  (CPI Ika approve_message)
 *   POST /close           → oidc_session_close
 *   POST /staging/close   → oidc_jwt_staging_close
 */

import { Router, type Response } from 'express'
import { z } from 'zod'
import { address as toAddress } from '@solana/kit'
import type { AppConfig } from '../../config.js'
import { logger } from '../../logger.js'
import { sanitizeError } from '../../safeError.js'
import { fail, ok } from '../../types.js'
import { getSolanaCtx } from '../adapters/SolanaAdapter.js'
import {
  fetchOidcStaging,
  jwsSigningInputDigest,
  prepareOidcSessionOpen,
  prepareOidcUse,
  submitOidcJwtStage,
  submitOidcJwtStagingClose,
  submitOidcSessionClose,
  submitOidcSessionOpen,
  submitOidcUse,
} from '../adapters/solana/oidc.js'
import {
  audienceHash as deriveAudienceHash,
  deriveAddrSeed,
  deriveOidcNonce,
  issuerHash as deriveIssuerHash,
  kidHash as deriveKidHash,
} from '../../oidc/derive.js'
import { IdTokenError, MAX_ID_TOKEN_LEN, verifyIdToken } from '../../oidc/verify.js'

// ── decoding helpers (mirror recovery/primary/routes.ts) ───────

function decodeB64Fixed(input: string, size: number, label: string): Uint8Array {
  if (
    input === '' &&
    size === 32 &&
    (label === 'metadataDigest' || label === 'metadata_digest')
  ) {
    return new Uint8Array(32)
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) throw new Error(`${label} must be valid base64`)
  const buf = Buffer.from(input, 'base64')
  if (buf.length !== size) throw new Error(`${label} must be ${size} bytes (got ${buf.length})`)
  return Uint8Array.from(buf)
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

// ── shared OIDC prep (read staging → verify JWT → derive) ──────

interface OidcDerived {
  jwtBytes: Uint8Array
  iss: string
  aud: string
  sub: string
  kid: string
  exp: number
  addrSeed: Uint8Array
  issuerHash: Uint8Array
  audienceHash: Uint8Array
  kidHash: Uint8Array
  jwtDigest: Uint8Array
}

/**
 * Reads the staged JWT, re-validates it server-side, checks `oidc_nonce` and
 * `not_after <= exp` (same as the on-chain verifier — done here to avoid a
 * wasted gas-sponsored tx), and returns the derived identifiers.
 */
async function deriveFromStagedJwt(
  config: AppConfig,
  stagingAddress: string,
  ephPk: Uint8Array,
  notAfterUnixTs: bigint,
  nonceRandomness: Uint8Array,
): Promise<OidcDerived> {
  const staging = await fetchOidcStaging(toAddress(stagingAddress))
  const jwtBytes = staging.jwt
  if (jwtBytes.length === 0 || jwtBytes.length > MAX_ID_TOKEN_LEN) {
    throw new IdTokenError('too_long', 'staged JWT length out of range')
  }
  const jwtString = Buffer.from(jwtBytes).toString('utf8')
  const v = await verifyIdToken(jwtString, config.oidc)
  if (deriveOidcNonce(ephPk, notAfterUnixTs, nonceRandomness) !== v.nonce) {
    throw new IdTokenError('nonce_mismatch', 'oidc_nonce does not match the JWT nonce claim')
  }
  if (BigInt(v.exp) < notAfterUnixTs) {
    throw new IdTokenError('exp_before_not_after', 'not_after is after the JWT exp')
  }
  return {
    jwtBytes,
    iss: v.iss,
    aud: v.aud,
    sub: v.sub,
    kid: v.kid,
    exp: v.exp,
    addrSeed: deriveAddrSeed(v.iss, v.aud, v.sub),
    issuerHash: deriveIssuerHash(v.iss),
    audienceHash: deriveAudienceHash(v.aud),
    kidHash: deriveKidHash(v.kid),
    jwtDigest: jwsSigningInputDigest(jwtBytes),
  }
}

// ── schemas ────────────────────────────────────────────────────

const stageSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  idToken: z.string().min(1).max(MAX_ID_TOKEN_LEN),
})

const openChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  stagingAddress: z.string().min(32),
  ephPkBase64: z.string(),
  notAfterUnixTs: z.coerce.bigint(),
  nonceRandomnessBase64: z.string(),
})

const openSubmitSchema = openChallengeSchema.extend({
  ephSignatureBase64: z.string(),
  expectedSessionNonce: z.coerce.bigint(),
})

const useChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  sessionAddress: z.string().min(32),
  messageDigestBase64: z.string(),
  metadataDigestBase64: z.string().default(''),
  userPubkeyBase64: z.string(),
  signatureScheme: z.number().int().min(0).max(6),
})

const useSubmitSchema = useChallengeSchema.extend({
  ephSignatureBase64: z.string(),
  expectedUseNonce: z.coerce.bigint(),
})

const closeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  sessionAddress: z.string().min(32),
})

const stagingCloseSchema = z.object({
  stagingAddress: z.string().min(32),
})

// ── router ─────────────────────────────────────────────────────

function handleError(context: string, e: unknown, res: Response): void {
  if (e instanceof IdTokenError) {
    logger.info({ context, reason: e.reason }, 'OIDC recovery: id_token rejected')
    res.status(400).json(fail('Invalid id_token'))
    return
  }
  const safe = sanitizeError(context, e)
  res.status(500).json(fail(safe.message, safe.traceId))
}

export function buildOidcRecoveryRouter(config: AppConfig): Router {
  const router = Router()

  // ── stage ──
  router.post('/stage', async (req, res) => {
    const parsed = stageSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      // Re-validate the id_token server-side before spending gas/rent.
      await verifyIdToken(parsed.data.idToken, config.oidc)
      const jwtBytes = new TextEncoder().encode(parsed.data.idToken)
      if (jwtBytes.length > MAX_ID_TOKEN_LEN) {
        return res.status(400).json(fail('id_token too long'))
      }
      const result = await submitOidcJwtStage(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        jwtBytes,
      })
      return res.json(
        ok({
          txSignature: result.txSignature,
          stagingAddress: result.stagingAddress,
          stagingNonce: result.stagingNonce.toString(),
        }),
      )
    } catch (e) {
      return handleError('recovery/oidc/stage', e, res)
    }
  })

  // ── open/challenge (read-only) ──
  router.post('/open/challenge', async (req, res) => {
    const parsed = openChallengeSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const ephPk = decodeB64Fixed(parsed.data.ephPkBase64, 32, 'ephPk')
      const nonceRandomness = decodeB64Fixed(parsed.data.nonceRandomnessBase64, 32, 'nonceRandomness')
      const d = await deriveFromStagedJwt(config, parsed.data.stagingAddress, ephPk, parsed.data.notAfterUnixTs, nonceRandomness)
      const out = await prepareOidcSessionOpen(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        ephPk,
        notAfterUnixTs: parsed.data.notAfterUnixTs,
        jwtDigest: d.jwtDigest,
        addrSeed: d.addrSeed,
      })
      return res.json(
        ok({
          challengeBase64: b64(out.challenge),
          expectedSessionNonce: out.expectedSessionNonce.toString(),
          sessionAddress: out.sessionAddress,
          jwkRegistryAddress: out.jwkRegistryAddress,
          jwkRegistryBump: out.jwkRegistryBump,
          oidcVerifierVersion: out.oidcVerifierVersion,
          addrSeedBase64: b64(d.addrSeed),
          jwtExpiresAt: d.exp,
        }),
      )
    } catch (e) {
      return handleError('recovery/oidc/open/challenge', e, res)
    }
  })

  // ── open (submit) ──
  router.post('/open', async (req, res) => {
    const parsed = openSubmitSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const ephPk = decodeB64Fixed(parsed.data.ephPkBase64, 32, 'ephPk')
      const nonceRandomness = decodeB64Fixed(parsed.data.nonceRandomnessBase64, 32, 'nonceRandomness')
      const ephSignature = decodeB64Fixed(parsed.data.ephSignatureBase64, 64, 'ephSignature')
      const d = await deriveFromStagedJwt(config, parsed.data.stagingAddress, ephPk, parsed.data.notAfterUnixTs, nonceRandomness)
      const result = await submitOidcSessionOpen(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        stagingAddress: parsed.data.stagingAddress,
        ephPk,
        notAfterUnixTs: parsed.data.notAfterUnixTs,
        nonceRandomness,
        jwtDigest: d.jwtDigest,
        addrSeed: d.addrSeed,
        ephSignature,
        expectedSessionNonce: parsed.data.expectedSessionNonce,
        issuerHash: d.issuerHash,
        audienceHash: d.audienceHash,
        kidHash: d.kidHash,
      })
      return res.json(ok({ txSignature: result.txSignature, sessionAddress: result.sessionAddress }))
    } catch (e) {
      return handleError('recovery/oidc/open', e, res)
    }
  })

  // ── use/challenge (read-only) ──
  router.post('/use/challenge', async (req, res) => {
    const parsed = useChallengeSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const messageDigest = decodeB64Fixed(parsed.data.messageDigestBase64, 32, 'messageDigest')
      const metadataDigest = decodeB64Fixed(parsed.data.metadataDigestBase64, 32, 'metadataDigest')
      const userPubkey = decodeB64Fixed(parsed.data.userPubkeyBase64, 32, 'userPubkey')
      const out = await prepareOidcUse(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        sessionAddress: parsed.data.sessionAddress,
        messageDigest,
        metadataDigest,
        userPubkey,
        signatureScheme: parsed.data.signatureScheme,
      })
      return res.json(
        ok({
          challengeBase64: b64(out.challenge),
          expectedUseNonce: out.expectedUseNonce.toString(),
          sessionExpiresAt: out.sessionExpiresAt,
        }),
      )
    } catch (e) {
      return handleError('recovery/oidc/use/challenge', e, res)
    }
  })

  // ── use/submit ──
  router.post('/use/submit', async (req, res) => {
    const parsed = useSubmitSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const messageDigest = decodeB64Fixed(parsed.data.messageDigestBase64, 32, 'messageDigest')
      const metadataDigest = decodeB64Fixed(parsed.data.metadataDigestBase64, 32, 'metadataDigest')
      const userPubkey = decodeB64Fixed(parsed.data.userPubkeyBase64, 32, 'userPubkey')
      const ephSignature = decodeB64Fixed(parsed.data.ephSignatureBase64, 64, 'ephSignature')
      const result = await submitOidcUse(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        sessionAddress: parsed.data.sessionAddress,
        messageDigest,
        metadataDigest,
        userPubkey,
        signatureScheme: parsed.data.signatureScheme,
        ephSignature,
        expectedUseNonce: parsed.data.expectedUseNonce,
      })
      return res.json(
        ok({ txSignature: result.txSignature, messageApprovalAddress: result.messageApprovalAddress }),
      )
    } catch (e) {
      return handleError('recovery/oidc/use/submit', e, res)
    }
  })

  // ── close ──
  router.post('/close', async (req, res) => {
    const parsed = closeSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const result = await submitOidcSessionClose(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        sessionAddress: parsed.data.sessionAddress,
      })
      return res.json(ok({ txSignature: result.txSignature }))
    } catch (e) {
      return handleError('recovery/oidc/close', e, res)
    }
  })

  // ── staging/close ──
  router.post('/staging/close', async (req, res) => {
    const parsed = stagingCloseSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const result = await submitOidcJwtStagingClose(ctx, { stagingAddress: parsed.data.stagingAddress })
      return res.json(ok({ txSignature: result.txSignature }))
    } catch (e) {
      return handleError('recovery/oidc/staging/close', e, res)
    }
  })

  return router
}
