// Email — magic link router.
// Mounted only when IKA_IDENTITY_EMAIL_ENABLED=true.

import { Router } from 'express'
import { handleEmailRequest, handleEmailVerify } from './flows.js'

export function buildEmailRouter(): Router {
  const router = Router()
  router.post('/request', handleEmailRequest)
  router.post('/verify', handleEmailVerify)
  return router
}
