import { describe, it, expect, beforeAll } from 'vitest'
import { loadAllVerifiers, listRegisteredSchemes, _resetRecoveryRegistry } from '../../verifiers/index.js'

describe('recovery discovery — verifiers registry', () => {
  beforeAll(async () => {
    _resetRecoveryRegistry()
    await loadAllVerifiers()
  })

  it('registers all expected schemes', () => {
    const schemes = listRegisteredSchemes().sort()
    expect(schemes).toEqual(
      [
        'ed25519-raw',
        'ed25519-near',
        'ed25519-aptos',
        'secp256k1-eip191',
        'secp256k1-adr036',
        'secp256k1-bitcoin',
        'sr25519-substrate',
      ].sort(),
    )
  })
})
