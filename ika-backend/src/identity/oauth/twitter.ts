// OAuth — Twitter / X provider (OAuth 2.0 + PKCE, no OIDC).

import type {
  AuthorizationRequestParams,
  BuiltAuthorizationUrl,
  ExchangeCodeInput,
  OauthProvider,
} from './providers.js'
import type { VerifiedOauthIdentity } from '../types.js'

const AUTHORIZATION_ENDPOINT = 'https://twitter.com/i/oauth2/authorize'
const TOKEN_ENDPOINT = 'https://api.twitter.com/2/oauth2/token'
const USER_ENDPOINT = 'https://api.twitter.com/2/users/me'
const FETCH_TIMEOUT_MS = 5_000

interface TwitterEnv {
  enabled: boolean
  clientId: string
  clientSecret: string
  redirectUris: string[]
}

function readTwitterEnv(): TwitterEnv {
  const enabled = (process.env.IKA_IDENTITY_OAUTH_TWITTER_ENABLED ?? '').trim().toLowerCase() === 'true'
  return {
    enabled,
    clientId: process.env.IKA_IDENTITY_OAUTH_TWITTER_CLIENT_ID?.trim() ?? '',
    clientSecret: process.env.IKA_IDENTITY_OAUTH_TWITTER_CLIENT_SECRET?.trim() ?? '',
    redirectUris: (process.env.IKA_IDENTITY_OAUTH_TWITTER_REDIRECT_URIS ?? '')
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean),
  }
}

function isMasterIdentityEnabled(): boolean {
  return (process.env.IKA_IDENTITY_ENABLED ?? '').trim().toLowerCase() === 'true'
}

interface TokenResponse {
  access_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
  refresh_token?: string
}

interface TwitterUserResponse {
  data?: {
    id?: string
    name?: string
    username?: string
  }
}

export const twitterOauthProvider: OauthProvider = {
  id: 'twitter',

  isConfigured() {
    const env = readTwitterEnv()
    return env.clientId.length > 0 && env.clientSecret.length > 0 && env.redirectUris.length > 0
  },

  isEnabled() {
    return isMasterIdentityEnabled() && readTwitterEnv().enabled && this.isConfigured()
  },

  isAllowedRedirectUri(redirectUri: string) {
    return readTwitterEnv().redirectUris.includes(redirectUri)
  },

  async buildAuthorizationUrl(params: AuthorizationRequestParams): Promise<BuiltAuthorizationUrl> {
    const env = readTwitterEnv()
    const url = new URL(AUTHORIZATION_ENDPOINT)
    url.searchParams.set('client_id', env.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'users.read tweet.read')
    url.searchParams.set('state', params.state)
    url.searchParams.set('code_challenge', params.codeChallenge)
    url.searchParams.set('code_challenge_method', params.codeChallengeMethod)
    return { authorizationUrl: url.toString() }
  },

  async exchangeAndVerify(input: ExchangeCodeInput): Promise<VerifiedOauthIdentity> {
    const env = readTwitterEnv()

    const basicAuth = Buffer.from(`${env.clientId}:${env.clientSecret}`).toString('base64')
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      code_verifier: input.codeVerifier,
      client_id: env.clientId,
    })
    const tokenController = new AbortController()
    const tokenTimer = setTimeout(() => tokenController.abort(), FETCH_TIMEOUT_MS)
    let tokenResponse: TokenResponse
    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: {
          authorization: `Basic ${basicAuth}`,
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: tokenBody,
        signal: tokenController.signal,
      })
      if (!response.ok) throw new Error(`Twitter token exchange failed: ${response.status}`)
      tokenResponse = (await response.json()) as TokenResponse
    } finally {
      clearTimeout(tokenTimer)
    }

    if (!tokenResponse.access_token) throw new Error('Twitter token exchange returned no access_token')

    const userController = new AbortController()
    const userTimer = setTimeout(() => userController.abort(), FETCH_TIMEOUT_MS)
    let user: TwitterUserResponse
    try {
      const response = await fetch(USER_ENDPOINT, {
        headers: {
          authorization: `Bearer ${tokenResponse.access_token}`,
          accept: 'application/json',
          'user-agent': 'ika-backend',
        },
        signal: userController.signal,
      })
      if (!response.ok) throw new Error(`Twitter /users/me request failed: ${response.status}`)
      user = (await response.json()) as TwitterUserResponse
    } finally {
      clearTimeout(userTimer)
    }

    const id = user.data?.id
    if (typeof id !== 'string' || id.length === 0) throw new Error('Twitter /users/me returned no id')

    return {
      provider: 'oauth-twitter',
      sub: id,
      email: null,
      displayName:
        typeof user.data?.name === 'string' && user.data.name.length > 0
          ? user.data.name
          : typeof user.data?.username === 'string'
            ? `@${user.data.username}`
            : null,
    }
  },
}

export function validateTwitterConfig(): string[] {
  const env = readTwitterEnv()
  if (!env.enabled) return []
  const errors: string[] = []
  if (!env.clientId) errors.push('IKA_IDENTITY_OAUTH_TWITTER_CLIENT_ID is required when Twitter is enabled.')
  if (!env.clientSecret) errors.push('IKA_IDENTITY_OAUTH_TWITTER_CLIENT_SECRET is required when Twitter is enabled.')
  if (env.redirectUris.length === 0) {
    errors.push('IKA_IDENTITY_OAUTH_TWITTER_REDIRECT_URIS must list at least one URI when Twitter is enabled.')
  }
  return errors
}
