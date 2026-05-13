/**
 * Login Social — `POST /v1/oidc/nonce` + `POST /v1/oidc/validate`
 * (loginsocial.md §6.1, §9, §10 table).
 *
 * `/nonce`: the obligatory pre-step — given the user's ephemeral Ed25519
 * public key, the backend picks `not_after` + `nonce_randomness` and returns
 * the canonical `oidc_nonce` to use as the OAuth `nonce`. This is the only
 * piece of crypto-layout knowledge the client would otherwise need; moving it
 * server-side keeps the client to "generate an Ed25519 key + sign 32-byte
 * challenges" — no SDK, no byte-layout code.
 *
 * `/validate`: the obligatory off-chain pre-check before any gas-sponsored
 * `stage`. Validates the `id_token` server-side (provider JWKS,
 * issuer/audience/sig/exp/iat/nbf, `alg`/`kid`, `sub`, `nonce` shape) and
 * returns only the derived public identifiers — never the raw `sub`, raw JWT,
 * or JWK internals. The on-chain `oidc-verifier` is still the final source of
 * truth.
 *
 * `X-Api-Key` is enforced by the mount router (`buildOidcMountRouter`).
 */

import { randomBytes } from 'node:crypto'
import { Router } from 'express'
import { z } from 'zod'
import type { OidcConfig } from '../config.js'
import { logger } from '../logger.js'
import { sanitizeError } from '../safeError.js'
import { fail, ok } from '../types.js'
import {
  audienceHash as deriveAudienceHash,
  deriveAddrSeed,
  deriveOidcNonce,
  issuerHash as deriveIssuerHash,
  subjectHash as deriveSubjectHash,
  toBase64,
} from './derive.js'
import { IdTokenError, MAX_ID_TOKEN_LEN, verifyIdToken } from './verify.js'

const validateSchema = z.object({
  idToken: z.string().min(1).max(MAX_ID_TOKEN_LEN),
})

// `/nonce`: ephPkBase64 is required; notAfterUnixTs is optional — when omitted
// the backend picks a safe default (now + DEFAULT_NOT_AFTER_SECONDS), which is
// ≤ the shortest provider id_token TTL (Apple ≈ 600 s from issuance) even after
// the OAuth round-trip, so the on-chain `exp >= not_after` check still passes.
const DEFAULT_NOT_AFTER_SECONDS = 540
// Past-the-hour `not_after` can never be ≤ a provider's `exp` — reject early.
const MAX_NOT_AFTER_AHEAD_SECONDS = 3600

const nonceSchema = z.object({
  ephPkBase64: z.string(),
  notAfterUnixTs: z.coerce.bigint().optional(),
})

function decodeFixed(input: string, size: number, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) throw new Error(`${label} must be valid base64`)
  const buf = Buffer.from(input, 'base64')
  if (buf.length !== size) throw new Error(`${label} must be ${size} bytes (got ${buf.length})`)
  return Uint8Array.from(buf)
}

export function buildOidcRouter(config: OidcConfig): Router {
  const hmacSecret = config.logSubjectHmacSecret
  if (!hmacSecret) {
    // Boot validation guarantees this when IKA_OIDC_ENABLED=true; defensive.
    throw new Error('oidc.logSubjectHmacSecret is required to build the OIDC router')
  }

  const router = Router()

  router.post('/nonce', (req, res) => {
    const parsed = nonceSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json(fail('Invalid request: ephPkBase64 (base64, 32 bytes) required'))
    }
    try {
      const ephPk = decodeFixed(parsed.data.ephPkBase64, 32, 'ephPkBase64')
      const now = BigInt(Math.floor(Date.now() / 1000))
      let notAfter: bigint
      if (parsed.data.notAfterUnixTs !== undefined) {
        notAfter = parsed.data.notAfterUnixTs
        if (notAfter <= now || notAfter > now + BigInt(MAX_NOT_AFTER_AHEAD_SECONDS)) {
          return res
            .status(400)
            .json(fail(`Invalid notAfterUnixTs: must be in (now, now + ${MAX_NOT_AFTER_AHEAD_SECONDS}]`))
        }
      } else {
        notAfter = now + BigInt(DEFAULT_NOT_AFTER_SECONDS)
      }
      const nonceRandomness = new Uint8Array(randomBytes(32))
      const oidcNonce = deriveOidcNonce(ephPk, notAfter, nonceRandomness)
      return res.json(
        ok({
          oidcNonce,
          notAfterUnixTs: Number(notAfter),
          nonceRandomnessBase64: toBase64(nonceRandomness),
        }),
      )
    } catch (e) {
      const safe = sanitizeError('oidc/nonce', e)
      return res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/validate', async (req, res) => {
    const parsed = validateSchema.safeParse(req.body)
    if (!parsed.success) {
      return res
        .status(400)
        .json(fail(`Invalid request: idToken (string, 1..=${MAX_ID_TOKEN_LEN} chars) required`))
    }
    try {
      const v = await verifyIdToken(parsed.data.idToken, config)
      const issuerHash = deriveIssuerHash(v.iss)
      const audienceHash = deriveAudienceHash(v.aud)
      const subjectHash = deriveSubjectHash(hmacSecret, v.iss, v.aud, v.sub)
      const addrSeed = deriveAddrSeed(v.iss, v.aud, v.sub)
      logger.info(
        {
          context: 'oidc/validate',
          provider: v.provider,
          issuerHash: toBase64(issuerHash),
          audienceHash: toBase64(audienceHash),
          subjectHash: toBase64(subjectHash),
          expiresAt: v.exp,
        },
        'OIDC id_token validated',
      )
      return res.json(
        ok({
          valid: true,
          provider: v.provider,
          addrSeed: toBase64(addrSeed),
          issuerHash: toBase64(issuerHash),
          audienceHash: toBase64(audienceHash),
          subjectHash: toBase64(subjectHash),
          expiresAt: v.exp,
        }),
      )
    } catch (e) {
      if (e instanceof IdTokenError) {
        // Structurally-fine request, invalid token — `valid: false`; the
        // reason stays server-side (no enumeration help for the caller).
        logger.info({ context: 'oidc/validate', reason: e.reason }, 'OIDC id_token rejected')
        return res.json(ok({ valid: false }))
      }
      const safe = sanitizeError('oidc/validate', e)
      return res.status(500).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
