// OAuth — GitHub provider (OAuth 2.0, no OIDC).

import type {
  AuthorizationRequestParams,
  BuiltAuthorizationUrl,
  ExchangeCodeInput,
  OauthProvider,
} from './providers.js'
import type { VerifiedOauthIdentity } from '../types.js'

const AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize'
const TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token'
const USER_ENDPOINT = 'https://api.github.com/user'
const FETCH_TIMEOUT_MS = 5_000

interface GithubEnv {
  enabled: boolean
  clientId: string
  clientSecret: string
  redirectUris: string[]
}

function readGithubEnv(): GithubEnv {
  const enabled = (process.env.IKA_IDENTITY_OAUTH_GITHUB_ENABLED ?? '').trim().toLowerCase() === 'true'
  return {
    enabled,
    clientId: process.env.IKA_IDENTITY_OAUTH_GITHUB_CLIENT_ID?.trim() ?? '',
    clientSecret: process.env.IKA_IDENTITY_OAUTH_GITHUB_CLIENT_SECRET?.trim() ?? '',
    redirectUris: (process.env.IKA_IDENTITY_OAUTH_GITHUB_REDIRECT_URIS ?? '')
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
  scope?: string
  error?: string
  error_description?: string
}

interface GithubUserResponse {
  id: number
  login: string
  name?: string | null
  email?: string | null
}

export const githubOauthProvider: OauthProvider = {
  id: 'github',

  isConfigured() {
    const env = readGithubEnv()
    return env.clientId.length > 0 && env.clientSecret.length > 0 && env.redirectUris.length > 0
  },

  isEnabled() {
    return isMasterIdentityEnabled() && readGithubEnv().enabled && this.isConfigured()
  },

  isAllowedRedirectUri(redirectUri: string) {
    return readGithubEnv().redirectUris.includes(redirectUri)
  },

  async buildAuthorizationUrl(params: AuthorizationRequestParams): Promise<BuiltAuthorizationUrl> {
    const env = readGithubEnv()
    const url = new URL(AUTHORIZATION_ENDPOINT)
    url.searchParams.set('client_id', env.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('scope', 'read:user user:email')
    url.searchParams.set('state', params.state)
    url.searchParams.set('code_challenge', params.codeChallenge)
    url.searchParams.set('code_challenge_method', params.codeChallengeMethod)
    return { authorizationUrl: url.toString() }
  },

  async exchangeAndVerify(input: ExchangeCodeInput): Promise<VerifiedOauthIdentity> {
    const env = readGithubEnv()

    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: env.clientId,
      client_secret: env.clientSecret,
    })
    const tokenController = new AbortController()
    const tokenTimer = setTimeout(() => tokenController.abort(), FETCH_TIMEOUT_MS)
    let tokenResponse: TokenResponse
    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: tokenBody,
        signal: tokenController.signal,
      })
      if (!response.ok) throw new Error(`GitHub token exchange failed: ${response.status}`)
      tokenResponse = (await response.json()) as TokenResponse
    } finally {
      clearTimeout(tokenTimer)
    }

    if (tokenResponse.error || !tokenResponse.access_token) {
      throw new Error(`GitHub token exchange returned no access_token: ${tokenResponse.error ?? 'unknown'}`)
    }

    const userController = new AbortController()
    const userTimer = setTimeout(() => userController.abort(), FETCH_TIMEOUT_MS)
    let user: GithubUserResponse
    try {
      const response = await fetch(USER_ENDPOINT, {
        headers: {
          authorization: `Bearer ${tokenResponse.access_token}`,
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'ika-backend',
        },
        signal: userController.signal,
      })
      if (!response.ok) throw new Error(`GitHub /user request failed: ${response.status}`)
      user = (await response.json()) as GithubUserResponse
    } finally {
      clearTimeout(userTimer)
    }

    if (typeof user.id !== 'number' || !Number.isFinite(user.id)) {
      throw new Error('GitHub /user returned no numeric id')
    }

    return {
      provider: 'oauth-github',
      sub: String(user.id),
      email: typeof user.email === 'string' && user.email.length > 0 ? user.email : null,
      displayName:
        typeof user.name === 'string' && user.name.length > 0
          ? user.name
          : typeof user.login === 'string'
            ? user.login
            : null,
    }
  },
}

export function validateGithubConfig(): string[] {
  const env = readGithubEnv()
  if (!env.enabled) return []
  const errors: string[] = []
  if (!env.clientId) errors.push('IKA_IDENTITY_OAUTH_GITHUB_CLIENT_ID is required when GitHub is enabled.')
  if (!env.clientSecret) errors.push('IKA_IDENTITY_OAUTH_GITHUB_CLIENT_SECRET is required when GitHub is enabled.')
  if (env.redirectUris.length === 0) {
    errors.push('IKA_IDENTITY_OAUTH_GITHUB_REDIRECT_URIS must list at least one URI when GitHub is enabled.')
  }
  return errors
}
