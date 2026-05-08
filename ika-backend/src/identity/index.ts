import { Router } from 'express'
import { ok } from '../types.js'
import type { AppConfig } from '../config.js'
import { logger } from '../logger.js'
import { getIdentityConfig, validateIdentityConfigOrThrow } from './config.js'
import { buildSessionRouter } from './session-routes.js'
import { assertConfigFingerprintImmutable, IDENTITY_CONFIG_KEYS } from './store.js'
import { buildPasskeyRouter } from './passkey/index.js'
import { buildEmailRouter } from './email/index.js'
import { buildOauthRouter, listEnabledOauthProviders, validateOauthProvidersConfig } from './oauth/index.js'
import { buildLinkingRouter } from './linking/index.js'

/**
 * Identity Layer router.
 *
 * Camadas:
 *   - foundation: types, derive, config, store, jwt, middleware, session, audit
 *   - sessões: GET /me, POST /refresh, /logout, GET /me/export, DELETE /me
 *   - providers: OAuth (Google/Apple/Twitter/GitHub), email magic-link, passkey-PRF
 *   - linking: /link/oauth/{start,callback}, /link/email/{request,verify},
 *              /link/passkey/register/{options,verify}, DELETE /link/:p/:s
 *
 * Cada provider só monta quando flag específica está ligada.
 */
export async function configureIdentityLayer(_config: AppConfig): Promise<void> {
  const ic = getIdentityConfig()
  validateIdentityConfigOrThrow(ic)
  const providerErrors = validateOauthProvidersConfig()
  if (providerErrors.length > 0) {
    throw new Error(
      `[ika-backend][identity/oauth] invalid configuration:\n  - ${providerErrors.join('\n  - ')}`,
    )
  }
  if (ic.providers.passkey && ic.passkey.prfSaltHex) {
    await assertConfigFingerprintImmutable(IDENTITY_CONFIG_KEYS.passkeyPrfSalt, ic.passkey.prfSaltHex)
  }
  logger.info(
    {
      providers: ic.providers,
      enabledOauth: listEnabledOauthProviders(),
      auditEnabled: ic.persistence.auditLogEnabled,
    },
    'Identity Layer configured',
  )
}

export function buildIdentityRouter(_config: AppConfig): Router {
  const router = Router()
  const ic = getIdentityConfig()

  router.get('/providers', (_req, res) => {
    res.json(
      ok({
        enabled: ic.enabled,
        providers: {
          google: ic.providers.oauthGoogle,
          apple: ic.providers.oauthApple,
          twitter: ic.providers.oauthTwitter,
          github: ic.providers.oauthGithub,
          email: ic.providers.email,
          passkey: ic.providers.passkey,
        },
        enabledOauth: listEnabledOauthProviders(),
      }),
    )
  })

  // Sessão (refresh público; demais user-auth)
  router.use(buildSessionRouter())

  // OAuth — sempre montado quando identity está ligada (handlers checam por
  // provider individualmente).
  router.use('/oauth', buildOauthRouter())

  // Email magic-link
  if (ic.providers.email) {
    router.use('/email', buildEmailRouter())
  }

  // Passkey-as-identity (PRF)
  if (ic.providers.passkey) {
    router.use('/passkey', buildPasskeyRouter())
  }

  // Account linking — Bearer JWT obrigatório (middleware aplicado no router).
  router.use('/link', buildLinkingRouter())

  return router
}
