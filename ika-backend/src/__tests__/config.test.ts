import { describe, it, expect } from 'vitest'
import { loadConfig } from '../config.js'

const baseEnv = {
  DATABASE_URL: 'postgresql://localhost/test',
  IKA_GRPC_URL: 'https://pre-alpha-dev-1.ika.ika-network.net:443',
  IKA_PROGRAM_ID: '87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY',
  SOLANA_RPC_URL: 'https://api.devnet.solana.com',
  INTERNAL_API_KEY: 'test-key-with-32-chars-or-more-padding',
}

describe('config', () => {
  it('loads with minimum env', () => {
    const config = loadConfig(baseEnv as NodeJS.ProcessEnv)
    expect(config.base.serviceApiKey).toBe('test-key-with-32-chars-or-more-padding')
    expect(config.base.solanaCommitment).toBe('confirmed')
    expect(config.recovery.enabled).toBe(false)
  })

  it('accepts policy enabled without program id (F11b-Phase4b: legacy fields no longer required)', () => {
    // The legacy rules-policy adapter was deleted; `policyEnabled` now only
    // gates the 410-sunset routers, so the program id / coordinator /
    // keypair fields are optional at boot.
    const config = loadConfig({
      ...baseEnv,
      IKA_RECOVERY_ENABLED: 'true',
      IKA_RECOVERY_POLICY_ENABLED: 'true',
    } as NodeJS.ProcessEnv)
    expect(config.recovery.policyEnabled).toBe(true)
  })
})
