import { Router } from 'express'
import { requireServiceApiKey } from '../http/auth.js'
import { loadAllVerifiers } from './verifiers/index.js'
import { buildDiscoveryRouter } from './discovery/routes.js'
import { buildLegacySunsetRouter } from './legacy-sunset.js'
import { logger } from '../logger.js'
import type { AppConfig } from '../config.js'

let verifiersLoaded = false

/**
 * F11b-Phase3 (2026-05-15): the legacy `/v1/recovery/{primary,quorum,policy,
 * passkey,oidc}/*` mutating flows are SUNSET — they return 410 Gone with a
 * pointer to the v3 surface on the gateway (`/v1/policy/*`). Discovery routes
 * (`/v1/recovery/{challenge,resolve}`) stay live: they're the credential →
 * dwallet *lookup* layer, not v3-replaceable.
 *
 * Old wiring (mounted the live handlers + `initSolanaAdapter`) is preserved in
 * git history; the active code keeps only what's reachable post-sunset.
 */
export async function buildRecoveryRouter(config: AppConfig): Promise<Router> {
  if (!verifiersLoaded) {
    await loadAllVerifiers()
    verifiersLoaded = true
  }

  const router = Router()
  router.use(requireServiceApiKey)

  // Discovery (live).
  router.use(buildDiscoveryRouter(config))

  if (config.recovery.policyEnabled) {
    logger.info(
      {
        replacement: '/v1/policy/*',
        oidcWasEnabled: config.oidc.enabled,
        passkeyWasEnabled: config.passkey.enabled,
      },
      'Recovery Layer: legacy mutating flows SUNSET (410). Use the gateway PolicyEngine v3 surface.',
    )

    router.use(
      '/primary',
      buildLegacySunsetRouter({
        category: 'primary',
        successorPath: '/v1/policy/recover-as-primary/challenge',
        message:
          'Primary-owner recovery moved to PolicyEngine v3. Use POST /v1/policy/recover-as-primary/{challenge,submit} on the gateway.',
      }),
    )
    router.use(
      '/quorum',
      buildLegacySunsetRouter({
        category: 'quorum',
        successorPath: '/v1/policy/quorum/session/open/challenge',
        message:
          'Quorum recovery moved to PolicyEngine v3. Use POST /v1/policy/quorum/session/{open,contribute}/{challenge,submit}, /v1/policy/quorum/session/finalize and /v1/policy/quorum/session/close on the gateway.',
      }),
    )
    router.use(
      '/policy',
      buildLegacySunsetRouter({
        category: 'policy',
        successorPath: '/v1/policy/init/challenge',
        message:
          'rules-policy deploy/admin moved to PolicyEngine v3. Use POST /v1/policy/init/{challenge,submit}, /v1/policy/rules/add/{challenge,submit} and /v1/policy/rules/{ruleIndex}/items/add/{challenge,submit} on the gateway.',
      }),
    )
  }

  return router
}
