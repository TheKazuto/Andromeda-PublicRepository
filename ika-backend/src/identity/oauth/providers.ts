// OAuth — provider abstraction. Generic flows.ts dispatches by id.

import type { VerifiedOauthIdentity } from '../types.js'

export type OauthProviderId = 'google' | 'apple' | 'twitter' | 'github'

export const OAUTH_PROVIDER_IDS: ReadonlyArray<OauthProviderId> = [
  'google',
  'apple',
  'twitter',
  'github',
] as const

export interface AuthorizationRequestParams {
  state: string
  codeChallenge: string
  codeChallengeMethod: 'S256'
  redirectUri: string
}

export interface BuiltAuthorizationUrl {
  authorizationUrl: string
}

export interface ExchangeCodeInput {
  code: string
  codeVerifier: string
  redirectUri: string
}

export interface OauthProvider {
  readonly id: OauthProviderId
  isConfigured(): boolean
  isEnabled(): boolean
  isAllowedRedirectUri(redirectUri: string): boolean
  buildAuthorizationUrl(params: AuthorizationRequestParams): Promise<BuiltAuthorizationUrl>
  exchangeAndVerify(input: ExchangeCodeInput): Promise<VerifiedOauthIdentity>
}

const registry = new Map<OauthProviderId, OauthProvider>()

export function registerOauthProvider(provider: OauthProvider): void {
  registry.set(provider.id, provider)
}

export function getOauthProvider(id: OauthProviderId): OauthProvider | null {
  return registry.get(id) ?? null
}

export function listEnabledOauthProviderIds(): OauthProviderId[] {
  return [...registry.values()].filter((p) => p.isEnabled()).map((p) => p.id)
}
