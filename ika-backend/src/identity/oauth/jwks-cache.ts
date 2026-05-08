// OAuth — JWKS verification cache + OpenID discovery cache.

import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose'

const JWKS_TTL_MS = 60 * 60 * 1000
const FETCH_TIMEOUT_MS = 5_000

interface CachedResolver {
  resolver: JWTVerifyGetKey
  fetchedAt: number
}

const resolverCache = new Map<string, CachedResolver>()

export function getJwksResolver(jwksUri: string): JWTVerifyGetKey {
  const cached = resolverCache.get(jwksUri)
  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) {
    return cached.resolver
  }
  const resolver = createRemoteJWKSet(new URL(jwksUri), {
    timeoutDuration: FETCH_TIMEOUT_MS,
    cooldownDuration: 30_000,
  })
  resolverCache.set(jwksUri, { resolver, fetchedAt: Date.now() })
  return resolver
}

interface OpenIdConfig {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
  [key: string]: unknown
}

interface CachedConfig {
  config: OpenIdConfig
  fetchedAt: number
}

const configCache = new Map<string, CachedConfig>()

export async function fetchOpenIdConfig(
  discoveryUrl: string,
  options: { timeoutMs?: number; force?: boolean } = {},
): Promise<OpenIdConfig> {
  const cached = configCache.get(discoveryUrl)
  if (!options.force && cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) {
    return cached.config
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? FETCH_TIMEOUT_MS)
  try {
    const response = await fetch(discoveryUrl, { signal: controller.signal })
    if (!response.ok) {
      throw new Error(`OpenID discovery failed: ${response.status} ${response.statusText}`)
    }
    const config = (await response.json()) as OpenIdConfig
    if (typeof config.issuer !== 'string' || typeof config.jwks_uri !== 'string') {
      throw new Error('OpenID discovery returned malformed document')
    }
    configCache.set(discoveryUrl, { config, fetchedAt: Date.now() })
    return config
  } finally {
    clearTimeout(timer)
  }
}

export function _resetJwksCaches(): void {
  resolverCache.clear()
  configCache.clear()
}
