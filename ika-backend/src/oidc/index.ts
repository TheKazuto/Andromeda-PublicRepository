/**
 * Login Social (`scheme = 4 = OidcJwt`) — `ika-backend` surface.
 *
 * Opt-in via `IKA_OIDC_ENABLED` (boot validation in `config.ts`). When
 * disabled this router is not mounted and the surface is identical to the
 * pre-OIDC backend.
 *
 * MVP scope (this module): the obligatory `POST /v1/oidc/validate` pre-check.
 * The gas-sponsored recovery adapters (`/v1/recovery/primary/oidc/{stage,open,
 * use/challenge,use/submit,close}`) live under the recovery router.
 *
 * Re-exports the derivation/verification helpers so the recovery adapters can
 * reuse them.
 */

import { Router } from 'express'
import { requireServiceApiKey } from '../http/auth.js'
import type { AppConfig } from '../config.js'
import { buildOidcRouter } from './routes.js'

export * from './derive.js'
export * from './verify.js'

/** Mountable at `/v1/oidc` — `X-Api-Key` enforced. */
export function buildOidcMountRouter(config: AppConfig): Router {
  const router = Router()
  router.use(requireServiceApiKey)
  router.use(buildOidcRouter(config.oidc))
  return router
}
