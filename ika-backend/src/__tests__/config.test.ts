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
    expect(config.oidc.enabled).toBe(false)
    expect(config.passkey.enabled).toBe(false)
  })
})
