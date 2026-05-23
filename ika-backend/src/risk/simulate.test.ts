/**
 * Tests for real EVM simulation (eth_call revert detection + estimateGas +
 * structured effects). viem's `createPublicClient` is mocked so no network is
 * touched; the rest of viem (serializeTransaction/parseTransaction/error
 * classes) stays real. Digests are computed with the same helpers the code
 * uses, so `digestMatches` is exercised honestly.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return { ...actual, createPublicClient: vi.fn() }
})

import { serializeTransaction, createPublicClient } from 'viem'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { simulateTransaction } from './simulate.js'
import { preProcessForChain } from '../chain/preprocess.js'
import { schemeDigest } from '../chain/digest.js'
import { resolveChainParams } from '../chain/chains.js'

const CHAIN = 'eip155:1'
const TOKEN = '0x1111111111111111111111111111111111111111'
const SPENDER_WORD = '000000000000000000000000ab12345678901234567890123456789012345678'
const MAX_UINT256 = 'f'.repeat(64)
// Public IP literal so the SSRF guard passes (createPublicClient is mocked, no real connection).
const RPC = 'http://1.2.3.4:8545'

// Deterministic secp256k1 public key for the dWallet — drives the EVM `from`.
const PUBKEY_HEX = Buffer.from(secp256k1.getPublicKey(new Uint8Array(32).fill(1), true)).toString('hex')

function buildApproveTx(): { serialized: `0x${string}`; digestHex: string } {
  const data = `0x095ea7b3${SPENDER_WORD}${MAX_UINT256}` as `0x${string}`
  const serialized = serializeTransaction({
    type: 'eip1559',
    chainId: 1,
    to: TOKEN,
    value: 0n,
    data,
    nonce: 0,
    gas: 60000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  })
  const params = resolveChainParams(CHAIN)
  const pre = preProcessForChain(CHAIN, new Uint8Array(Buffer.from(serialized.slice(2), 'hex')), 'transaction')
  const digestHex = Buffer.from(schemeDigest(params.scheme, pre)!).toString('hex')
  return { serialized, digestHex }
}

function mockClient(client: { call: unknown; estimateGas?: unknown }): void {
  vi.mocked(createPublicClient).mockReturnValue(client as never)
}

describe('EVM simulation via eth_call', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('simulates a successful approve: verified, gas estimated, unlimited approval extracted', async () => {
    const { serialized, digestHex } = buildApproveTx()
    mockClient({
      call: vi.fn().mockResolvedValue({ data: '0x' }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
    })

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: digestHex, dwalletPublicKeyHex: PUBKEY_HEX },
      RPC,
    )

    expect(res.digestMatches).toBe(true)
    expect(res.verified).toBe(true)
    expect(res.willRevert).toBe(false)
    expect(res.effectsExtracted).toBe(true)
    expect(res.estimatedGas).toBe('21000')
    expect(res.approvals[0]).toEqual({ token: TOKEN, spender: '0xab12345678901234567890123456789012345678', amount: 'unlimited' })
    expect(res.calls[0]).toEqual({ address: TOKEN, method: '0x095ea7b3' })
  })

  it('reports a real on-chain revert as willRevert (not an RPC failure)', async () => {
    const { serialized, digestHex } = buildApproveTx()
    mockClient({
      call: vi.fn().mockRejectedValue(new Error('execution reverted: ERC20: insufficient allowance')),
    })

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: digestHex, dwalletPublicKeyHex: PUBKEY_HEX },
      RPC,
    )

    expect(res.willRevert).toBe(true)
    expect(res.ok).toBe(false)
    expect(res.verified).toBe(true)
    expect(res.warnings.some((w) => w.toLowerCase().includes('revert'))).toBe(true)
  })

  it('degrades honestly to static analysis when the RPC is unreachable', async () => {
    const { serialized, digestHex } = buildApproveTx()
    mockClient({
      call: vi.fn().mockRejectedValue(new Error('HTTP request failed: connection refused')),
    })

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: digestHex, dwalletPublicKeyHex: PUBKEY_HEX },
      RPC,
    )

    expect(res.verified).toBe(false)
    expect(res.effectsExtracted).toBe(false)
    expect(res.willRevert).toBe(false)
    expect(res.warnings[0]).toContain('EVM RPC unavailable')
    // Static effects are still surfaced.
    expect(res.approvals[0]?.amount).toBe('unlimited')
  })

  it('rejects a digest mismatch before calling the RPC', async () => {
    const { serialized } = buildApproveTx()
    const callMock = vi.fn()
    mockClient({ call: callMock })

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: '00'.repeat(32) },
      RPC,
    )

    expect(res.digestMatches).toBe(false)
    expect(res.verified).toBe(false)
    expect(callMock).not.toHaveBeenCalled()
  })

  it('falls back to static effects when the client provides no RPC URL', async () => {
    const { serialized, digestHex } = buildApproveTx()

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: digestHex },
      undefined,
    )

    expect(res.digestMatches).toBe(true)
    expect(res.verified).toBe(false)
    expect(res.effectsExtracted).toBe(false)
    expect(res.approvals[0]?.amount).toBe('unlimited')
    expect(res.warnings[0]).toContain('No RPC URL provided')
  })

  it('rejects a client RPC URL that targets a private address (SSRF guard)', async () => {
    const { serialized, digestHex } = buildApproveTx()
    const callMock = vi.fn()
    mockClient({ call: callMock })

    const res = await simulateTransaction(
      { chainId: CHAIN, payloadHex: serialized, kind: 'transaction', expectedDigestHex: digestHex, dwalletPublicKeyHex: PUBKEY_HEX },
      'http://127.0.0.1:8545',
    )

    expect(res.verified).toBe(false)
    expect(res.effectsExtracted).toBe(false)
    expect(res.warnings[0]).toContain('rejected')
    expect(callMock).not.toHaveBeenCalled()
  })
})
