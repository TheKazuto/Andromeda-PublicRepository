import { describe, it, expect } from 'vitest'
import { loadConfig } from '../config.js'

const baseEnv = {
  DATABASE_URL: 'postgresql://localhost/test',
  IKA_GRPC_URL: 'https://pre-alpha-dev-1.ika.ika-network.net:443',
  IKA_PROGRAM_ID: '87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY',
  SOLANA_RPC_URL: 'https://api.devnet.solana.com',
  INTERNAL_API_KEY: 'test-key',
}

describe('config', () => {
  it('loads with minimum env', () => {
    const config = loadConfig(baseEnv as NodeJS.ProcessEnv)
    expect(config.base.serviceApiKey).toBe('test-key')
    expect(config.base.solanaCommitment).toBe('confirmed')
    expect(config.recovery.enabled).toBe(false)
  })

  it('rejects identity enabled without jwt secret', () => {
    expect(() =>
      loadConfig({ ...baseEnv, IKA_IDENTITY_ENABLED: 'true' } as NodeJS.ProcessEnv),
    ).toThrow(/jwtSecret/)
  })

  it('rejects policy enabled without program id', () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        IKA_RECOVERY_ENABLED: 'true',
        IKA_RECOVERY_POLICY_ENABLED: 'true',
      } as NodeJS.ProcessEnv),
    ).toThrow(/policyProgramId|gasSponsor/)
  })

  it('accepts policy enabled with program id and sponsor', () => {
    const config = loadConfig({
      ...baseEnv,
      IKA_RECOVERY_ENABLED: 'true',
      IKA_RECOVERY_POLICY_ENABLED: 'true',
      IKA_RECOVERY_POLICY_PROGRAM_ID: 'RuLeSPoLiCy1111111111111111111111111111111',
      IKA_GAS_SPONSOR_KEYPAIR: 'base58-encoded-keypair-or-path',
      IKA_COORDINATOR_ADDRESS: 'V5giRyf1Rk9Lhn7sjq6LYnBv6TN8ZgSuRx654mPdYoA',
    } as NodeJS.ProcessEnv)
    expect(config.recovery.policyEnabled).toBe(true)
  })
})
