// OAuth — Google provider (OpenID Connect + PKCE).

import { jwtVerify } from 'jose'
import { fetchOpenIdConfig, getJwksResolver } from './jwks-cache.js'
import type {
  AuthorizationRequestParams,
  BuiltAuthorizationUrl,
  ExchangeCodeInput,
  OauthProvider,
} from './providers.js'
import type { VerifiedOauthIdentity } from '../types.js'

const GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
const TOKEN_FETCH_TIMEOUT_MS = 5_000

interface GoogleConfigEnv {
  enabled: boolean
  clientId: string
  clientSecret: string
  redirectUris: string[]
}

function readGoogleEnv(): GoogleConfigEnv {
  const enabled = (process.env.IKA_IDENTITY_OAUTH_GOOGLE_ENABLED ?? '').toLowerCase().trim() === 'true'
  const clientId = process.env.IKA_IDENTITY_OAUTH_GOOGLE_CLIENT_ID?.trim() ?? ''
  const clientSecret = process.env.IKA_IDENTITY_OAUTH_GOOGLE_CLIENT_SECRET?.trim() ?? ''
  const redirectUris = (process.env.IKA_IDENTITY_OAUTH_GOOGLE_REDIRECT_URIS ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
  return { enabled, clientId, clientSecret, redirectUris }
}

function isMasterIdentityEnabled(): boolean {
  return (process.env.IKA_IDENTITY_ENABLED ?? '').toLowerCase().trim() === 'true'
}

interface TokenResponse {
  access_token?: string
  id_token?: string
  refresh_token?: string
  expires_in?: number
  scope?: string
  token_type?: string
}

interface GoogleIdTokenClaims {
  iss?: string
  sub?: string
  aud?: string
  exp?: number
  iat?: number
  email?: string
  email_verified?: boolean
  name?: string
}

export const googleOauthProvider: OauthProvider = {
  id: 'google',

  isConfigured() {
    const env = readGoogleEnv()
    return env.clientId.length > 0 && env.clientSecret.length > 0 && env.redirectUris.length > 0
  },

  isEnabled() {
    return isMasterIdentityEnabled() && readGoogleEnv().enabled && this.isConfigured()
  },

  isAllowedRedirectUri(redirectUri: string) {
    return readGoogleEnv().redirectUris.includes(redirectUri)
  },

  async buildAuthorizationUrl(params: AuthorizationRequestParams): Promise<BuiltAuthorizationUrl> {
    const env = readGoogleEnv()
    const config = await fetchOpenIdConfig(GOOGLE_DISCOVERY_URL)
    const url = new URL(config.authorization_endpoint)
    url.searchParams.set('client_id', env.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'openid email')
    url.searchParams.set('state', params.state)
    url.searchParams.set('code_challenge', params.codeChallenge)
    url.searchParams.set('code_challenge_method', params.codeChallengeMethod)
    url.searchParams.set('prompt', 'select_account')
    return { authorizationUrl: url.toString() }
  },

  async exchangeAndVerify(input: ExchangeCodeInput): Promise<VerifiedOauthIdentity> {
    const env = readGoogleEnv()
    const config = await fetchOpenIdConfig(GOOGLE_DISCOVERY_URL)

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      code_verifier: input.codeVerifier,
      redirect_uri: input.redirectUri,
      client_id: env.clientId,
      client_secret: env.clientSecret,
    })
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), TOKEN_FETCH_TIMEOUT_MS)
    let tokenResponse: TokenResponse
    try {
      const response = await fetch(config.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body,
        signal: controller.signal,
      })
      if (!response.ok) throw new Error(`Google token exchange failed: ${response.status}`)
      tokenResponse = (await response.json()) as TokenResponse
    } finally {
      clearTimeout(timer)
    }

    if (!tokenResponse.id_token) throw new Error('Google token response missing id_token')

    const jwks = getJwksResolver(config.jwks_uri)
    const { payload } = await jwtVerify(tokenResponse.id_token, jwks, {
      issuer: config.issuer,
      audience: env.clientId,
      clockTolerance: 5,
    })
    const claims = payload as GoogleIdTokenClaims

    if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
      throw new Error('Google id_token missing sub claim')
    }

    return {
      provider: 'oauth-google',
      sub: claims.sub,
      email: typeof claims.email === 'string' ? claims.email : null,
      displayName: typeof claims.name === 'string' ? claims.name : null,
    }
  },
}

export function validateGoogleConfig(): string[] {
  if (!readGoogleEnv().enabled) return []
  const env = readGoogleEnv()
  const errors: string[] = []
  if (!env.clientId) errors.push('IKA_IDENTITY_OAUTH_GOOGLE_CLIENT_ID is required when Google is enabled.')
  if (!env.clientSecret) errors.push('IKA_IDENTITY_OAUTH_GOOGLE_CLIENT_SECRET is required when Google is enabled.')
  if (env.redirectUris.length === 0) {
    errors.push('IKA_IDENTITY_OAUTH_GOOGLE_REDIRECT_URIS must list at least one URI when Google is enabled.')
  }
  return errors
}
