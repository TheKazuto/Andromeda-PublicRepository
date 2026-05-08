// OAuth — Sign in with Apple (OIDC + ES256 client_secret JWT).

import { importPKCS8, jwtVerify, SignJWT } from 'jose'
import { fetchOpenIdConfig, getJwksResolver } from './jwks-cache.js'
import type {
  AuthorizationRequestParams,
  BuiltAuthorizationUrl,
  ExchangeCodeInput,
  OauthProvider,
} from './providers.js'
import type { VerifiedOauthIdentity } from '../types.js'

const DISCOVERY_URL = 'https://appleid.apple.com/.well-known/openid-configuration'
const APPLE_AUDIENCE = 'https://appleid.apple.com'
const CLIENT_SECRET_TTL_SECONDS = 300
const FETCH_TIMEOUT_MS = 5_000

interface AppleEnv {
  enabled: boolean
  clientId: string
  teamId: string
  keyId: string
  privateKeyPem: string
  redirectUris: string[]
}

function normalizePrivateKey(raw: string): string {
  return raw.trim().replace(/\\n/g, '\n')
}

function readAppleEnv(): AppleEnv {
  const enabled = (process.env.IKA_IDENTITY_OAUTH_APPLE_ENABLED ?? '').trim().toLowerCase() === 'true'
  return {
    enabled,
    clientId: process.env.IKA_IDENTITY_OAUTH_APPLE_CLIENT_ID?.trim() ?? '',
    teamId: process.env.IKA_IDENTITY_OAUTH_APPLE_TEAM_ID?.trim() ?? '',
    keyId: process.env.IKA_IDENTITY_OAUTH_APPLE_KEY_ID?.trim() ?? '',
    privateKeyPem: normalizePrivateKey(process.env.IKA_IDENTITY_OAUTH_APPLE_PRIVATE_KEY ?? ''),
    redirectUris: (process.env.IKA_IDENTITY_OAUTH_APPLE_REDIRECT_URIS ?? '')
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean),
  }
}

function isMasterIdentityEnabled(): boolean {
  return (process.env.IKA_IDENTITY_ENABLED ?? '').trim().toLowerCase() === 'true'
}

type ImportedKey = Awaited<ReturnType<typeof importPKCS8>>

let cachedKey: { source: string; key: ImportedKey } | null = null
async function importApplePrivateKey(pem: string): Promise<ImportedKey> {
  if (cachedKey && cachedKey.source === pem) return cachedKey.key
  const key = await importPKCS8(pem, 'ES256')
  cachedKey = { source: pem, key }
  return cachedKey.key
}

async function buildClientSecretJwt(env: AppleEnv): Promise<string> {
  const key = await importApplePrivateKey(env.privateKeyPem)
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: env.keyId })
    .setIssuer(env.teamId)
    .setSubject(env.clientId)
    .setAudience(APPLE_AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + CLIENT_SECRET_TTL_SECONDS)
    .sign(key)
}

interface TokenResponse {
  access_token?: string
  expires_in?: number
  id_token?: string
  refresh_token?: string
  token_type?: string
}

interface AppleIdTokenClaims {
  iss?: string
  sub?: string
  aud?: string
  exp?: number
  iat?: number
  email?: string
  email_verified?: boolean | string
  is_private_email?: boolean | string
}

export const appleOauthProvider: OauthProvider = {
  id: 'apple',

  isConfigured() {
    const env = readAppleEnv()
    return (
      env.clientId.length > 0 &&
      env.teamId.length > 0 &&
      env.keyId.length > 0 &&
      env.privateKeyPem.length > 0 &&
      env.redirectUris.length > 0
    )
  },

  isEnabled() {
    return isMasterIdentityEnabled() && readAppleEnv().enabled && this.isConfigured()
  },

  isAllowedRedirectUri(redirectUri: string) {
    return readAppleEnv().redirectUris.includes(redirectUri)
  },

  async buildAuthorizationUrl(params: AuthorizationRequestParams): Promise<BuiltAuthorizationUrl> {
    const env = readAppleEnv()
    const config = await fetchOpenIdConfig(DISCOVERY_URL)
    const url = new URL(config.authorization_endpoint)
    url.searchParams.set('client_id', env.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'openid email')
    url.searchParams.set('state', params.state)
    url.searchParams.set('code_challenge', params.codeChallenge)
    url.searchParams.set('code_challenge_method', params.codeChallengeMethod)
    return { authorizationUrl: url.toString() }
  },

  async exchangeAndVerify(input: ExchangeCodeInput): Promise<VerifiedOauthIdentity> {
    const env = readAppleEnv()
    const config = await fetchOpenIdConfig(DISCOVERY_URL)
    const clientSecret = await buildClientSecretJwt(env)

    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      code_verifier: input.codeVerifier,
      redirect_uri: input.redirectUri,
      client_id: env.clientId,
      client_secret: clientSecret,
    })
    const tokenController = new AbortController()
    const tokenTimer = setTimeout(() => tokenController.abort(), FETCH_TIMEOUT_MS)
    let tokenResponse: TokenResponse
    try {
      const response = await fetch(config.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: tokenBody,
        signal: tokenController.signal,
      })
      if (!response.ok) throw new Error(`Apple token exchange failed: ${response.status}`)
      tokenResponse = (await response.json()) as TokenResponse
    } finally {
      clearTimeout(tokenTimer)
    }

    if (!tokenResponse.id_token) throw new Error('Apple token response missing id_token')

    const jwks = getJwksResolver(config.jwks_uri)
    const { payload } = await jwtVerify(tokenResponse.id_token, jwks, {
      issuer: config.issuer,
      audience: env.clientId,
      clockTolerance: 5,
    })
    const claims = payload as AppleIdTokenClaims

    if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
      throw new Error('Apple id_token missing sub claim')
    }

    const email = typeof claims.email === 'string' && claims.email.length > 0 ? claims.email : null

    return {
      provider: 'oauth-apple',
      sub: claims.sub,
      email,
      displayName: null,
    }
  },
}

export function validateAppleConfig(): string[] {
  const env = readAppleEnv()
  if (!env.enabled) return []
  const errors: string[] = []
  if (!env.clientId) errors.push('IKA_IDENTITY_OAUTH_APPLE_CLIENT_ID is required when Apple is enabled.')
  if (!env.teamId) errors.push('IKA_IDENTITY_OAUTH_APPLE_TEAM_ID is required when Apple is enabled.')
  if (!env.keyId) errors.push('IKA_IDENTITY_OAUTH_APPLE_KEY_ID is required when Apple is enabled.')
  if (!env.privateKeyPem) {
    errors.push(
      'IKA_IDENTITY_OAUTH_APPLE_PRIVATE_KEY is required when Apple is enabled (PKCS#8 PEM, .p8 file contents).',
    )
  } else if (!env.privateKeyPem.includes('BEGIN PRIVATE KEY') && !env.privateKeyPem.includes('BEGIN EC PRIVATE KEY')) {
    errors.push('IKA_IDENTITY_OAUTH_APPLE_PRIVATE_KEY does not look like a PEM-encoded private key.')
  }
  if (env.redirectUris.length === 0) {
    errors.push('IKA_IDENTITY_OAUTH_APPLE_REDIRECT_URIS must list at least one URI when Apple is enabled.')
  }
  return errors
}

export function _resetAppleKeyCache(): void {
  cachedKey = null
}
