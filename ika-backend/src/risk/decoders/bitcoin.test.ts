import { describe, it, expect } from 'vitest'
import { bitcoinDecoder } from './bitcoin.js'

// ── Raw-tx builder (legacy format; enough to exercise output decoding) ────────

function u64le(n: bigint): number[] {
  const out: number[] = []
  let v = n
  for (let i = 0; i < 8; i += 1) {
    out.push(Number(v & 0xffn))
    v >>= 8n
  }
  return out
}

function varint(n: number): number[] {
  if (n < 0xfd) return [n]
  if (n <= 0xffff) return [0xfd, n & 0xff, (n >> 8) & 0xff]
  return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
}

function hexBytes(hex: string): number[] {
  return [...Buffer.from(hex, 'hex')]
}

function buildTx(outputs: { valueSats: bigint; scriptHex: string }[]): string {
  const bytes: number[] = []
  bytes.push(1, 0, 0, 0) // version
  bytes.push(1) // 1 input
  bytes.push(...new Array(32).fill(0)) // prevout txid
  bytes.push(0, 0, 0, 0) // prevout vout
  bytes.push(0) // empty scriptSig
  bytes.push(0xff, 0xff, 0xff, 0xff) // sequence
  bytes.push(...varint(outputs.length))
  for (const o of outputs) {
    bytes.push(...u64le(o.valueSats))
    const script = hexBytes(o.scriptHex)
    bytes.push(...varint(script.length))
    bytes.push(...script)
  }
  bytes.push(0, 0, 0, 0) // locktime
  return `0x${Buffer.from(bytes).toString('hex')}`
}

const mainnet = { chainId: 'bip122:000000000019d6689c085ae165831e93', namespace: 'bip122', reference: '000000000019d6689c085ae165831e93' }

// BIP173 test vector: P2WPKH program → bech32 address.
const P2WPKH_SCRIPT = '0014751e76e8199196d454941c45d1b3a323f1433bd6'
const P2WPKH_ADDR = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
// Classic P2PKH example (hash160 → base58check, version 0x00).
const P2PKH_SCRIPT = '76a914010966776006953d5567439e5e39f86a0d273bee88ac'
const P2PKH_ADDR = '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'

describe('bitcoinDecoder', () => {
  it('decodes a P2WPKH output to its bech32 address + amount', () => {
    const tx = buildTx([{ valueSats: 100_000_000n, scriptHex: P2WPKH_SCRIPT }])
    const r = bitcoinDecoder.decode(tx, 'transaction', mainnet)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain(P2WPKH_ADDR)
    expect(r.reasons[0]).toContain('1 BTC')
  })

  it('decodes a P2PKH output to its base58check address', () => {
    const tx = buildTx([{ valueSats: 50_000_000n, scriptHex: P2PKH_SCRIPT }])
    const r = bitcoinDecoder.decode(tx, 'transaction', mainnet)
    expect(r.effectsExtracted).toBe(true)
    expect(r.reasons.join(' ')).toContain(P2PKH_ADDR)
    expect(r.reasons[0]).toContain('0.5 BTC')
  })

  it('flags OP_RETURN as low and non-standard scripts as medium', () => {
    const opReturn = bitcoinDecoder.decode(
      buildTx([{ valueSats: 0n, scriptHex: '6a48656c6c6f' }]),
      'transaction',
      mainnet,
    )
    expect(opReturn.level).toBe('low')

    const nonStd = bitcoinDecoder.decode(
      buildTx([{ valueSats: 1000n, scriptHex: 'abcdef' }]),
      'transaction',
      mainnet,
    )
    expect(nonStd.level).toBe('medium')
  })

  it('degrades honestly on an undecodable payload', () => {
    const r = bitcoinDecoder.decode('0xdead', 'transaction', mainnet)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = bitcoinDecoder.decode('0xdeadbeef', 'message', mainnet)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
  })
})
