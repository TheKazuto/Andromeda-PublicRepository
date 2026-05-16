/**
 * Login Social (`scheme = 4 = OidcJwt`) — `ika-backend` surface.
 *
 * Opt-in via `IKA_OIDC_ENABLED` (boot validation in `config.ts`). When
 * disabled this router is not mounted.
 *
 * Scope (this module): the read-only helpers `POST /v1/oidc/nonce` and
 * `POST /v1/oidc/validate`. They produce the canonical OAuth `nonce` and
 * pre-validate the provider `id_token` (JWKS + claims) before any gas is
 * spent on-chain. The on-chain OIDC primary recovery (PolicyEngine v3 F9c)
 * is currently blocked on the `sol_big_mod_exp` syscall and will plug into
 * these helpers when it lands.
 *
 * Re-exports the derivation/verification helpers so future PolicyEngine v3
 * OIDC adapters can reuse them.
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
