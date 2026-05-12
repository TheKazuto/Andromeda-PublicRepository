// Account linking — router builder. Bearer JWT required.

import { Router } from 'express'
import { getIdentityConfig } from '../config.js'
import { requireUserAuth } from '../middleware.js'
import { handleLinkOauthCallback, handleLinkOauthStart } from './oauth.js'
import { handleLinkEmailRequest, handleLinkEmailVerify } from './email.js'
import { handleLinkPasskeyRegisterOptions, handleLinkPasskeyRegisterVerify } from './passkey.js'
import { handleDeleteLink } from './delete.js'

export function buildLinkingRouter(): Router {
  const router = Router()
  router.use(requireUserAuth)

  router.post('/oauth/start', handleLinkOauthStart)
  router.post('/oauth/callback', handleLinkOauthCallback)

  const config = getIdentityConfig()
  if (config.providers.email) {
    router.post('/email/request', handleLinkEmailRequest)
    router.post('/email/verify', handleLinkEmailVerify)
  }
  if (config.providers.passkey) {
    router.post('/passkey/register/options', handleLinkPasskeyRegisterOptions)
    router.post('/passkey/register/verify', handleLinkPasskeyRegisterVerify)
  }

  router.delete('/:provider/:subject', handleDeleteLink)

  return router
}
