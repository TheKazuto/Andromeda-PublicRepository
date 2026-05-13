/**
 * Login Social — obligatory server-side `id_token` pre-validation
 * (loginsocial.md §6.2 / §9). This is the `POST /v1/oidc/validate` check that
 * MUST pass before any gas-sponsored `stage`; the on-chain `oidc-verifier`
 * (`rules-policy` `scheme = 4`) remains the final source of truth — this layer
 * exists to cut gas/rent DoS and improve UX.
 *
 * Validates: provider `iss` is allowlisted; `aud` is a string in the env
 * allowlist; signature against the provider JWKS (`jose` `createRemoteJWKSet`
 * — cached, timed-out, retried); `alg == "RS256"`; a `kid` is present; no
 * `crit`/`jku`/`x5u` header; `sub` non-empty; `nonce` is a 43-char base64url
 * string (the on-chain verifier re-binds it to `eph_pk`/`not_after`); `exp` in
 * the future; `iat` not in the future beyond skew; `nbf <= now + skew`;
 * `exp - iat` within a plausible lifetime; JWT ≤ 4 KB.
 *
 * Never returns the raw `sub`, raw JWT, or JWK internals.
 */

import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose'
import type { OidcConfig } from '../config.js'

/** Hard cap on a presented JWT — mirrors `oidc-verifier::MAX_JWT_LEN`. */
export const MAX_ID_TOKEN_LEN = 4096
/** Clock skew tolerance for `iat`/`nbf` (seconds) — mirrors the on-chain `SKEW_SECONDS`. */
export const SKEW_SECONDS = 300
/** Upper bound on `exp - iat` (seconds) — mirrors the on-chain `MAX_TOKEN_LIFETIME_SECONDS`. */
export const MAX_TOKEN_LIFETIME_SECONDS = 4 * 3600

export type OidcProvider = 'google' | 'apple'

interface ProviderSpec {
  /** Acceptable `iss` claim values. */
  issuers: string[]
  /** JWKS endpoint. */
  jwksUri: string
}

const PROVIDERS: Record<OidcProvider, ProviderSpec> = {
  google: {
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
  },
  apple: {
    issuers: ['https://appleid.apple.com'],
    jwksUri: 'https://appleid.apple.com/auth/keys',
  },
}

// `jose` JWKSet getters are stateful caches (default 30s cooldown, ~5min max
// age) — create one per provider, lazily, and reuse it.
const jwksCache = new Map<OidcProvider, ReturnType<typeof createRemoteJWKSet>>()

function getJwks(provider: OidcProvider): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(provider)
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(PROVIDERS[provider].jwksUri), {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 5 * 60_000,
    })
    jwksCache.set(provider, jwks)
  }
  return jwks
}

/** Internal: reset the JWKS caches (tests). */
export function _resetJwksCaches(): void {
  jwksCache.clear()
}

export interface VerifiedIdToken {
  provider: OidcProvider
  iss: string
  aud: string
  sub: string
  nonce: string
  kid: string
  /** Issued-at, seconds. */
  iat: number
  /** Expiry, seconds. */
  exp: number
}

export class IdTokenError extends Error {
  /** A short, non-sensitive reason tag (safe to log; not necessarily for the client). */
  readonly reason: string
  constructor(reason: string, message?: string) {
    super(message ?? reason)
    this.reason = reason
  }
}

const NONCE_RE = /^[A-Za-z0-9_-]{43}$/

function enabledProviders(config: OidcConfig): Set<OidcProvider> {
  const set = new Set<OidcProvider>()
  if (config.googleEnabled) set.add('google')
  if (config.appleEnabled) set.add('apple')
  return set
}

function providerForIssuer(iss: string, enabled: Set<OidcProvider>): OidcProvider | null {
  for (const p of enabled) {
    if (PROVIDERS[p].issuers.includes(iss)) return p
  }
  return null
}

/**
 * Verifies an `id_token` against the configured providers. Throws
 * `IdTokenError` (with a non-sensitive `reason`) on any failure.
 */
export async function verifyIdToken(idToken: string, config: OidcConfig): Promise<VerifiedIdToken> {
  if (typeof idToken !== 'string' || idToken.length === 0) {
    throw new IdTokenError('empty')
  }
  if (idToken.length > MAX_ID_TOKEN_LEN) {
    throw new IdTokenError('too_long')
  }
  if (config.allowedAudiences.length === 0) {
    throw new IdTokenError('bad_config', 'no allowed audiences configured')
  }
  const enabled = enabledProviders(config)
  if (enabled.size === 0) {
    throw new IdTokenError('bad_config', 'no OIDC providers enabled')
  }

  // 1. strict header check (no verification yet — just structural).
  let header: ReturnType<typeof decodeProtectedHeader>
  try {
    header = decodeProtectedHeader(idToken)
  } catch {
    throw new IdTokenError('malformed_header')
  }
  if (header.alg !== 'RS256') throw new IdTokenError('unsupported_alg')
  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new IdTokenError('missing_kid')
  }
  if ('crit' in header || 'jku' in header || 'x5u' in header) {
    throw new IdTokenError('forbidden_header')
  }

  // 2. peek at `iss` to pick the provider (still unverified).
  let unverified: ReturnType<typeof decodeJwt>
  try {
    unverified = decodeJwt(idToken)
  } catch {
    throw new IdTokenError('malformed_claims')
  }
  const issClaim = unverified.iss
  if (typeof issClaim !== 'string') throw new IdTokenError('missing_iss')
  const provider = providerForIssuer(issClaim, enabled)
  if (!provider) throw new IdTokenError('issuer_not_allowed')

  // 3. verify signature + iss + aud + exp + nbf against the provider's JWKS.
  let payload: Awaited<ReturnType<typeof jwtVerify>>['payload']
  try {
    const result = await jwtVerify(idToken, getJwks(provider), {
      algorithms: ['RS256'],
      issuer: PROVIDERS[provider].issuers,
      audience: config.allowedAudiences,
      clockTolerance: SKEW_SECONDS,
    })
    payload = result.payload
  } catch (e) {
    // `jose` throws JWTClaimValidationFailed / JWSSignatureVerificationFailed /
    // JWKSNoMatchingKey / fetch errors — all collapse to a single tag here.
    const code = (e as { code?: string }).code
    if (code === 'ERR_JWT_EXPIRED') throw new IdTokenError('expired')
    if (code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') throw new IdTokenError('claim_invalid')
    if (code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') throw new IdTokenError('bad_signature')
    if (code === 'ERR_JWKS_NO_MATCHING_KEY') throw new IdTokenError('unknown_kid')
    throw new IdTokenError('verify_failed', (e as Error).message)
  }

  // ── claims are authentic from here ──

  // `aud` must be a single string (reject arrays — out of scope, §6.7).
  if (typeof payload.aud !== 'string') throw new IdTokenError('aud_not_string')
  const aud = payload.aud
  if (!config.allowedAudiences.includes(aud)) throw new IdTokenError('audience_not_allowed')

  const iss = typeof payload.iss === 'string' ? payload.iss : ''
  if (!PROVIDERS[provider].issuers.includes(iss)) throw new IdTokenError('issuer_not_allowed')

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new IdTokenError('missing_sub')
  }
  const sub = payload.sub

  if (typeof payload.nonce !== 'string' || !NONCE_RE.test(payload.nonce)) {
    throw new IdTokenError('bad_nonce')
  }
  const nonce = payload.nonce

  if (typeof payload.iat !== 'number' || !Number.isInteger(payload.iat)) {
    throw new IdTokenError('bad_iat')
  }
  if (typeof payload.exp !== 'number' || !Number.isInteger(payload.exp)) {
    throw new IdTokenError('bad_exp')
  }
  const iat = payload.iat
  const exp = payload.exp
  const now = Math.floor(Date.now() / 1000)
  if (iat > now + SKEW_SECONDS) throw new IdTokenError('issued_in_future')
  if (exp <= now) throw new IdTokenError('expired')
  if (exp < iat || exp - iat > MAX_TOKEN_LIFETIME_SECONDS) {
    throw new IdTokenError('implausible_lifetime')
  }
  if (typeof payload.nbf === 'number') {
    if (!Number.isInteger(payload.nbf)) throw new IdTokenError('bad_nbf')
    if (payload.nbf > now + SKEW_SECONDS) throw new IdTokenError('not_yet_valid')
  }

  return { provider, iss, aud, sub, nonce, kid: header.kid, iat, exp }
}
