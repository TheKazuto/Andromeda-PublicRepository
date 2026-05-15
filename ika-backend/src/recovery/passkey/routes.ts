/**
 * Passkey-primary recovery routes (Keyspring Fase 3, Bloco 2).
 *
 * Mounted at `/v1/recovery/primary/passkey/*` under the recovery router's
 * `X-Api-Key` middleware. The user signs a WebAuthn assertion over
 * `passkey_session_open_challenge` at open time, then signs each per-use
 * `passkey_primary_use_challenge` with the ephemeral Ed25519 key committed
 * at open. The on-chain `rules-policy` (`scheme = 3 = WebAuthn` session
 * flow — D1 Opção A) is the only authority.
 *
 *   POST /open/challenge   → (read-only) challenge for the WebAuthn assertion
 *   POST /open             → passkey_session_open (Secp256r1 precompile + ix 25)
 *   POST /use/challenge    → (read-only) per-use challenge for the ephemeral key
 *   POST /use/submit       → recover_as_primary_passkey_session (Ed25519 precompile + CPI Ika)
 *   POST /close            → passkey_session_close
 *   GET  /capabilities     → environment capabilities (rp_id, salt mode, TTLs, bounds)
 *
 * `revoke` is intentionally not here — it lives one level up at the dWallet
 * level (`POST /v1/recovery/passkey/credentials/:id/revoke`) once the
 * recovery_bindings store helpers land in Bloco 3.
 */

import { Router, type Response } from 'express'
import { z } from 'zod'
import type { AppConfig } from '../../config.js'
import { logger } from '../../logger.js'
import { sanitizeError } from '../../safeError.js'
import { fail, ok } from '../../types.js'
import {
  PASSKEY_SESSION_TTL_SECONDS,
  WEBAUTHN_AUTH_DATA_MAX,
  WEBAUTHN_CLIENT_DATA_JSON_MAX,
} from '../../clients/rulesPolicy/index.js'
import { getSolanaCtx } from '../adapters/SolanaAdapter.js'
import {
  preparePasskeySessionOpen,
  preparePasskeyUse,
  submitPasskeySessionClose,
  submitPasskeySessionOpen,
  submitPasskeyUse,
} from '../adapters/solana/passkey.js'
import {
  consumePasskeyChallenge,
  DuplicateCredentialError,
  insertPasskeyChallenge,
  LastActiveCredentialError,
  listActivePasskeyCredentials,
  MAX_CREDENTIALS_PER_DWALLET,
  MaxCredentialsPerDwalletError,
  newRegisterChallenge,
  registerPasskeyCredential,
  revokePasskeyCredential,
} from './store.js'
import {
  NoRpConfiguredError,
  OriginNotAllowedError,
  RpIdNotMatchingOriginError,
  parseAllowedOrigins,
  resolveRp,
} from './origins.js'

// Tenant resolver — the recovery router protects every route with
// `requireServiceApiKey`, which only authenticates the engine itself. In a
// multi-tenant deploy the gateway forwards the originating tenant id via
// `X-Tenant-Id`; we fall back to a single-tenant placeholder for dev/local
// so the per-tenant scoping still partitions rows correctly.
function tenantOf(req: { header: (name: string) => string | undefined }): string {
  return req.header('x-tenant-id') ?? 'default'
}

// ── decoding helpers (mirror recovery/oidc/routes.ts) ───────────

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

function decodeB64Bounded(input: string, maxLen: number, label: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) throw new Error(`${label} must be valid base64`)
  const buf = Buffer.from(input, 'base64')
  if (buf.length === 0) throw new Error(`${label} must not be empty`)
  if (buf.length > maxLen) throw new Error(`${label} too long: ${buf.length} > ${maxLen} bytes`)
  return Uint8Array.from(buf)
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

// ── schemas ────────────────────────────────────────────────────

const openChallengeSchema = z.object({
  dwalletAddress: z.string().min(32),
  initAuthorityHashBase64: z.string(),
  credentialPubkeyBase64: z.string(),
  credentialIdHashBase64: z.string(),
  ephPkBase64: z.string(),
  notAfterUnixTs: z.coerce.bigint(),
})

const openSubmitSchema = openChallengeSchema.extend({
  webauthnAuthDataBase64: z.string(),
  webauthnClientDataJsonBase64: z.string(),
  webauthnSignatureBase64: z.string(),
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

const registerInitSchema = z.object({
  dwalletAddress: z.string().min(32),
  /** Optional — required when the key has multiple `allowed_origins`. */
  rpOrigin: z.string().url().optional(),
  /** Optional — defaults to the registrable apex of `rpOrigin`'s host. */
  rpId: z.string().min(1).optional(),
})

const registerCompleteSchema = z.object({
  challengeId: z.string().uuid(),
  dwalletAddress: z.string().min(32),
  credentialIdHashBase64: z.string(),
  credentialPublicKeyBase64: z.string(),
  encPubKeyBase64: z.string().optional(),
  saltIdBase64: z.string(),
  saltHashBase64: z.string(),
  signCount: z.coerce.bigint().default(0n),
  backupEligible: z.boolean().default(false),
  backupState: z.boolean().default(false),
  transports: z.array(z.string()).default([]),
})

const revokeSchema = z.object({
  credentialId: z.string().uuid(),
})

// ── router ─────────────────────────────────────────────────────

function handleError(context: string, e: unknown, res: Response): void {
  // Typed business errors → explicit status codes BEFORE sanitization so the
  // client sees a stable error code, not a generic 500.
  if (e instanceof MaxCredentialsPerDwalletError) {
    res.status(409).json(fail('max_credentials_per_dwallet'))
    return
  }
  if (e instanceof DuplicateCredentialError) {
    res.status(409).json(fail('credential_already_registered'))
    return
  }
  if (e instanceof LastActiveCredentialError) {
    res.status(409).json(fail('last_active_credential'))
    return
  }
  if (e instanceof OriginNotAllowedError) {
    res.status(403).json(fail('origin_not_allowed'))
    return
  }
  if (e instanceof RpIdNotMatchingOriginError) {
    res.status(400).json(fail('rp_id_not_matching_origin'))
    return
  }
  if (e instanceof NoRpConfiguredError) {
    res.status(412).json(fail('passkey_rp_not_configured'))
    return
  }
  const safe = sanitizeError(context, e)
  const status = isClientError(e) ? 400 : 500
  res.status(status).json(fail(safe.message, safe.traceId))
}

function isClientError(e: unknown): boolean {
  if (!(e instanceof Error)) return false
  const m = e.message
  return (
    m.includes('must be') ||
    m.includes('too long') ||
    m.includes('expired') ||
    m.includes('does not belong') ||
    m.includes('nonce mismatch') ||
    m.includes('credential_pubkey does not match') ||
    m.includes('policy primary is not') ||
    m.includes('clientDataJSON does not anchor') ||
    m.includes('challenge') // covers "challenge not found", "challenge expired", …
  )
}

export function buildPasskeyRecoveryRouter(config: AppConfig): Router {
  const router = Router()

  // ── open/challenge (read-only) ──
  router.post('/open/challenge', async (req, res) => {
    const parsed = openChallengeSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const credentialPubkey = decodeB64Fixed(parsed.data.credentialPubkeyBase64, 33, 'credentialPubkey')
      const credentialIdHash = decodeB64Fixed(parsed.data.credentialIdHashBase64, 32, 'credentialIdHash')
      const ephPk = decodeB64Fixed(parsed.data.ephPkBase64, 32, 'ephPk')
      const out = await preparePasskeySessionOpen(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        credentialPubkey,
        credentialIdHash,
        ephPk,
        notAfterUnixTs: parsed.data.notAfterUnixTs,
      })
      return res.json(
        ok({
          challengeBase64: b64(out.challenge),
          humanMessage: out.humanMessage,
          clearSigning: out.clearSigning,
          expectedSessionNonce: out.expectedSessionNonce.toString(),
          sessionAddress: out.sessionAddress,
          // RP ID is part of the WebAuthn binding; the client passes it to
          // `navigator.credentials.get({ publicKey: { rpId, … } })`. Returning
          // it from the same endpoint that produced the challenge avoids any
          // config drift between dashboard and engine.
          rpId: config.passkey.rpId ?? null,
        }),
      )
    } catch (e) {
      return handleError('recovery/passkey/open/challenge', e, res)
    }
  })

  // ── open (submit) ──
  router.post('/open', async (req, res) => {
    const parsed = openSubmitSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const credentialPubkey = decodeB64Fixed(parsed.data.credentialPubkeyBase64, 33, 'credentialPubkey')
      const credentialIdHash = decodeB64Fixed(parsed.data.credentialIdHashBase64, 32, 'credentialIdHash')
      const ephPk = decodeB64Fixed(parsed.data.ephPkBase64, 32, 'ephPk')
      const webauthnAuthData = decodeB64Bounded(
        parsed.data.webauthnAuthDataBase64,
        WEBAUTHN_AUTH_DATA_MAX,
        'webauthnAuthData',
      )
      const webauthnClientDataJson = decodeB64Bounded(
        parsed.data.webauthnClientDataJsonBase64,
        WEBAUTHN_CLIENT_DATA_JSON_MAX,
        'webauthnClientDataJson',
      )
      const webauthnSignature = decodeB64Fixed(parsed.data.webauthnSignatureBase64, 64, 'webauthnSignature')
      const result = await submitPasskeySessionOpen(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        credentialPubkey,
        credentialIdHash,
        ephPk,
        notAfterUnixTs: parsed.data.notAfterUnixTs,
        webauthnAuthData,
        webauthnClientDataJson,
        webauthnSignature,
        expectedSessionNonce: parsed.data.expectedSessionNonce,
      })
      return res.json(ok({ txSignature: result.txSignature, sessionAddress: result.sessionAddress }))
    } catch (e) {
      return handleError('recovery/passkey/open', e, res)
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
      const out = await preparePasskeyUse(ctx, {
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
          humanMessage: out.humanMessage,
          clearSigning: out.clearSigning,
          expectedUseNonce: out.expectedUseNonce.toString(),
          sessionExpiresAt: out.sessionExpiresAt,
        }),
      )
    } catch (e) {
      return handleError('recovery/passkey/use/challenge', e, res)
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
      const result = await submitPasskeyUse(ctx, {
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
      return handleError('recovery/passkey/use/submit', e, res)
    }
  })

  // ── close ──
  router.post('/close', async (req, res) => {
    const parsed = closeSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const ctx = getSolanaCtx()
      const initAuthorityHash = decodeB64Fixed(parsed.data.initAuthorityHashBase64, 32, 'initAuthorityHash')
      const result = await submitPasskeySessionClose(ctx, {
        dwalletAddress: parsed.data.dwalletAddress,
        initAuthorityHash,
        sessionAddress: parsed.data.sessionAddress,
      })
      return res.json(ok({ txSignature: result.txSignature }))
    } catch (e) {
      return handleError('recovery/passkey/close', e, res)
    }
  })

  // ── credentials/register-init ───────────────────────────────
  //
  // Generates a fresh 32-byte challenge the browser will pass to
  // `navigator.credentials.create({ publicKey: { challenge, … } })`. The
  // challenge is single-use (consumed by /credentials/register-complete) and
  // bound to the dWallet that asked for it. Not on-chain — registration is
  // an off-chain bookkeeping step (the credential only matters on-chain when
  // it lands in `policy.primary_slot` via a separate admin tx).
  router.post('/credentials/register-init', async (req, res) => {
    const parsed = registerInitSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const rp = resolveRp({
        allowedOrigins: parseAllowedOrigins(req),
        requestedOrigin: parsed.data.rpOrigin,
        requestedRpId: parsed.data.rpId,
        envRpOrigin: config.passkey.rpOrigin,
        envRpId: config.passkey.rpId,
      })
      const challenge = newRegisterChallenge()
      const row = await insertPasskeyChallenge({
        tenantId: tenantOf(req),
        purpose: 'register',
        challenge,
        dwalletAddress: parsed.data.dwalletAddress,
        // The resolved RP is pinned into the challenge metadata so
        // register-complete uses the same pair without re-deriving it (and
        // can't be tricked by a different rpId on the second call).
        metadata: { rpId: rp.rpId, rpOrigin: rp.rpOrigin },
        ttlSeconds: config.passkey.challengeTtlSeconds,
      })
      return res.json(
        ok({
          challengeId: row.id,
          challengeBase64: b64(challenge),
          expiresAt: row.expires_at.toISOString(),
          rpId: rp.rpId,
          rpOrigin: rp.rpOrigin,
        }),
      )
    } catch (e) {
      return handleError('recovery/passkey/credentials/register-init', e, res)
    }
  })

  // ── credentials/register-complete ───────────────────────────
  //
  // Consumes the single-use challenge, then persists the credential under
  // the dWallet. D6 hard-limit (5 per dwallet) is enforced inside the
  // transaction in `registerPasskeyCredential` via SELECT … FOR UPDATE so
  // concurrent registers can't both win the 5th slot.
  //
  // NOTE: full WebAuthn attestation verification (cert chain, AAGUID
  // allowlist, etc.) is intentionally deferred for the MVP. The on-chain
  // policy verifies the assertion at use time, so an unverified attestation
  // at registration is bookkeeping noise, not a security gap. AAGUID gating
  // can be layered later from the gateway without touching this route.
  router.post('/credentials/register-complete', async (req, res) => {
    const parsed = registerCompleteSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const tenantId = tenantOf(req)
      const challenge = await consumePasskeyChallenge(tenantId, parsed.data.challengeId)
      if (!challenge) {
        return res.status(400).json(fail('challenge not found or expired'))
      }
      if (challenge.purpose !== 'register') {
        return res.status(400).json(fail('challenge purpose mismatch'))
      }
      if (challenge.dwallet_address && challenge.dwallet_address !== parsed.data.dwalletAddress) {
        return res.status(400).json(fail('challenge dwallet mismatch'))
      }
      const credentialIdHash = decodeB64Fixed(
        parsed.data.credentialIdHashBase64,
        32,
        'credentialIdHash',
      )
      const credentialPublicKey = decodeB64Fixed(
        parsed.data.credentialPublicKeyBase64,
        33,
        'credentialPublicKey',
      )
      const saltId = decodeB64Fixed(parsed.data.saltIdBase64, 16, 'saltId')
      const saltHash = decodeB64Fixed(parsed.data.saltHashBase64, 32, 'saltHash')
      const encPubKey = parsed.data.encPubKeyBase64
        ? decodeB64Bounded(parsed.data.encPubKeyBase64, 65, 'encPubKey')
        : undefined
      // RP was pinned into the challenge metadata at register-init time —
      // re-using it here closes the door on a client trying to swap rpId
      // between -init and -complete. Fall back to env only if the challenge
      // was issued by an older deploy (no metadata field).
      const meta = (challenge.metadata ?? {}) as { rpId?: string; rpOrigin?: string }
      const rpId = meta.rpId ?? config.passkey.rpId
      const origin = meta.rpOrigin ?? config.passkey.rpOrigin
      if (!rpId || !origin) {
        return res.status(412).json(fail('passkey_rp_not_configured'))
      }
      const view = await registerPasskeyCredential({
        tenantId,
        dwalletAddress: parsed.data.dwalletAddress,
        credentialIdHash,
        credentialPublicKey,
        encPubKey,
        rpId,
        origin,
        saltId,
        saltHash,
        signCount: parsed.data.signCount,
        backupEligible: parsed.data.backupEligible,
        backupState: parsed.data.backupState,
        transports: parsed.data.transports,
      })
      return res.json(
        ok({
          id: view.id,
          dwalletAddress: view.dwalletAddress,
          credentialIdHashBase64: b64(view.credentialIdHash),
          credentialPublicKeyBase64: b64(view.credentialPublicKey),
          createdAt: view.createdAt.toISOString(),
        }),
      )
    } catch (e) {
      return handleError('recovery/passkey/credentials/register-complete', e, res)
    }
  })

  // ── credentials (GET) ──────────────────────────────────────
  //
  // Lists active passkey credentials on a dWallet for the dashboard. Returns
  // only public metadata — never the raw credentialId (D12) nor the PRF
  // secret (it never leaves the browser).
  router.get('/credentials', async (req, res) => {
    const dw = req.query.dwalletAddress
    if (typeof dw !== 'string' || dw.length < 32) {
      return res.status(400).json(fail('dwalletAddress query param required'))
    }
    try {
      const rows = await listActivePasskeyCredentials(tenantOf(req), dw)
      return res.json(
        ok({
          credentials: rows.map((c) => ({
            id: c.id,
            dwalletAddress: c.dwalletAddress,
            credentialIdHashBase64: b64(c.credentialIdHash),
            credentialPublicKeyBase64: b64(c.credentialPublicKey),
            rpId: c.rpId,
            origin: c.origin,
            backupEligible: c.backupEligible,
            backupState: c.backupState,
            transports: c.transports,
            signCount: c.signCount.toString(),
            createdAt: c.createdAt.toISOString(),
            lastUsedAt: c.lastUsedAt ? c.lastUsedAt.toISOString() : null,
          })),
          limit: MAX_CREDENTIALS_PER_DWALLET,
          active: rows.length,
        }),
      )
    } catch (e) {
      return handleError('recovery/passkey/credentials/list', e, res)
    }
  })

  // ── credentials/:id/revoke ─────────────────────────────────
  //
  // D5 invariant: never revoke the LAST active recovery method. Enforced in
  // a single transaction inside `revokePasskeyCredential` — surfaces
  // HTTP 409 `last_active_credential` when triggered.
  router.post('/credentials/:id/revoke', async (req, res) => {
    const parsed = revokeSchema.safeParse({ credentialId: req.params['id'] })
    if (!parsed.success) return res.status(400).json(fail('Invalid request'))
    try {
      const view = await revokePasskeyCredential({
        tenantId: tenantOf(req),
        credentialId: parsed.data.credentialId,
      })
      if (!view) return res.status(404).json(fail('credential not found'))
      return res.json(
        ok({ id: view.id, revokedAt: view.revokedAt?.toISOString() ?? null }),
      )
    } catch (e) {
      return handleError('recovery/passkey/credentials/revoke', e, res)
    }
  })

  // ── capabilities (read-only, no Solana hit) ──
  //
  // Echoes the tenant's allowed_origins (forwarded by the gateway as
  // `X-Andromeda-Allowed-Origins`) so the frontend knows which origins are
  // valid for WebAuthn. When the header is absent (admin calling without a
  // configured allowlist — Andromeda dashboard path), falls back to the env
  // defaults.
  router.get('/capabilities', (req, res) => {
    const allowed = parseAllowedOrigins(req)
    const allowedOrigins = allowed.length > 0
      ? allowed
      : config.passkey.rpOrigin
        ? [config.passkey.rpOrigin]
        : []
    res.json(
      ok({
        enabled: true,
        allowedOrigins,
        // Convenience defaults for clients with a single allowed origin.
        // Multi-origin clients ignore these and pass rpId/rpOrigin per call.
        defaultRpId: allowed.length === 1
          ? null /* let the client derive — multiple apex strategies are valid */
          : (config.passkey.rpId ?? null),
        defaultRpOrigin: allowed.length === 1 ? allowed[0] : (config.passkey.rpOrigin ?? null),
        saltMode: config.passkey.saltMode,
        challengeTtlSeconds: config.passkey.challengeTtlSeconds,
        sessionTtlSeconds: config.passkey.sessionTtlSeconds,
        onChainSessionTtlSeconds: PASSKEY_SESSION_TTL_SECONDS,
        webauthnAuthDataMaxBytes: WEBAUTHN_AUTH_DATA_MAX,
        webauthnClientDataJsonMaxBytes: WEBAUTHN_CLIENT_DATA_JSON_MAX,
      }),
    )
  })

  logger.info({}, 'Recovery Layer: passkey-PRF (Keyspring D1 Opção A) routes mounted')
  return router
}
