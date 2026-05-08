// Passkey-as-identity — router builder.
// Mounted only when IKA_IDENTITY_PASSKEY_ENABLED=true. PRF salt fingerprint
// is asserted in identity/index.ts before this router is constructed.

import { Router } from 'express'
import {
  handlePasskeyAuthenticateOptions,
  handlePasskeyAuthenticateVerify,
  handlePasskeyRegisterOptions,
  handlePasskeyRegisterVerify,
} from './flows.js'

export function buildPasskeyRouter(): Router {
  const router = Router()
  router.post('/register/options', handlePasskeyRegisterOptions)
  router.post('/register/verify', handlePasskeyRegisterVerify)
  router.post('/authenticate/options', handlePasskeyAuthenticateOptions)
  router.post('/authenticate/verify', handlePasskeyAuthenticateVerify)
  return router
}
