import { Router } from 'express'
import { requireServiceApiKey } from '../http/auth.js'
import { initGasSponsor } from '../engine/gas-sponsor.js'
import { loadAllVerifiers } from './verifiers/index.js'
import { buildDiscoveryRouter } from './discovery/routes.js'
import { buildPrimaryRouter } from './primary/routes.js'
import { buildQuorumRouter } from './quorum/routes.js'
import { buildPolicyRouter } from './policy/routes.js'
import { buildOidcRecoveryRouter } from './oidc/routes.js'
import { buildPasskeyRecoveryRouter } from './passkey/routes.js'
import { initSolanaAdapter } from './adapters/SolanaAdapter.js'
import { logger } from '../logger.js'
import type { AppConfig } from '../config.js'

let verifiersLoaded = false

export async function buildRecoveryRouter(config: AppConfig): Promise<Router> {
  if (!verifiersLoaded) {
    await loadAllVerifiers()
    verifiersLoaded = true
  }

  const router = Router()
  router.use(requireServiceApiKey)

  // Discovery is always available when recovery is enabled.
  router.use(buildDiscoveryRouter(config))

  // Policy paths require the on-chain RulesPolicy program (sub-flag).
  if (config.recovery.policyEnabled) {
    if (!config.recovery.policyProgramId) {
      throw new Error('IKA_RECOVERY_POLICY_PROGRAM_ID must be set when policy is enabled')
    }
    if (!config.gasSponsor.keypair) {
      throw new Error('ANDROMEDA_GAS_SPONSOR_KEYPAIR must be set when policy is enabled')
    }
    await initGasSponsor(config.gasSponsor.keypair, {
      minBalanceSol: config.gasSponsor.minBalanceSol,
      maxGasPerOpLamports: config.gasSponsor.maxGasPerOpLamports,
    })
    initSolanaAdapter({
      programId: config.recovery.policyProgramId,
      ikaProgramId: config.base.ikaProgramId,
      ikaCoordinatorAddress: config.recovery.ikaCoordinatorAddress,
      defaultCooldownSeconds: config.recovery.defaultCooldownSeconds,
      minCooldownSeconds: config.recovery.minCooldownSeconds,
      oidcJwkRegistryAddress: config.oidc.enabled ? config.oidc.jwkRegistryAddress : undefined,
      oidcVerifierVersion: config.oidc.enabled ? config.oidc.verifierVersion : undefined,
    })
    const primaryRouter = buildPrimaryRouter()
    // Login Social — mount the OIDC primary-recovery flows under
    // `/v1/recovery/primary/oidc/*` when enabled (requires the policy program +
    // gas sponsor, already ensured above).
    if (config.oidc.enabled) {
      logger.info(
        { google: config.oidc.googleEnabled, apple: config.oidc.appleEnabled },
        'Recovery Layer: Login Social (OIDC) primary flows enabled',
      )
      primaryRouter.use('/oidc', buildOidcRecoveryRouter(config))
    }
    // Keyspring Fase 3 — passkey primary flows under
    // `/v1/recovery/primary/passkey/*`. Requires the policy program + gas
    // sponsor (already ensured above) and IKA_PASSKEY_ENABLED=true.
    if (config.passkey.enabled) {
      logger.info(
        { rpId: config.passkey.rpId, saltMode: config.passkey.saltMode },
        'Recovery Layer: passkey-PRF primary flows enabled',
      )
      primaryRouter.use('/passkey', buildPasskeyRecoveryRouter(config))
    }
    router.use('/primary', primaryRouter)
    router.use('/quorum', buildQuorumRouter(config))
    router.use('/policy', buildPolicyRouter(config))
  }

  return router
}
