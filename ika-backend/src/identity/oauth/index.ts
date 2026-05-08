// OAuth — router mount.

import { Router } from 'express'
import { appleOauthProvider, validateAppleConfig } from './apple.js'
import { handleOauthCallback, handleOauthStart } from './flows.js'
import { githubOauthProvider, validateGithubConfig } from './github.js'
import { googleOauthProvider, validateGoogleConfig } from './google.js'
import { listEnabledOauthProviderIds, registerOauthProvider } from './providers.js'
import { twitterOauthProvider, validateTwitterConfig } from './twitter.js'

let registered = false

function ensureProvidersRegistered(): void {
  if (registered) return
  registerOauthProvider(googleOauthProvider)
  registerOauthProvider(appleOauthProvider)
  registerOauthProvider(twitterOauthProvider)
  registerOauthProvider(githubOauthProvider)
  registered = true
}

export function buildOauthRouter(): Router {
  ensureProvidersRegistered()
  const router = Router()
  router.post('/start', handleOauthStart)
  router.post('/callback', handleOauthCallback)
  return router
}

export function listEnabledOauthProviders(): string[] {
  ensureProvidersRegistered()
  return listEnabledOauthProviderIds()
}

export function validateOauthProvidersConfig(): string[] {
  return [
    ...validateGoogleConfig(),
    ...validateAppleConfig(),
    ...validateTwitterConfig(),
    ...validateGithubConfig(),
  ]
}
