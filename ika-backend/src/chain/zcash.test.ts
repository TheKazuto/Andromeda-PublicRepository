import { describe, expect, it } from 'vitest'
import { blake2b } from '@noble/hashes/blake2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import {
  buildZip243Preimage,
  zcashSigHashPersonal,
  ZCASH_BRANCH_NU5,
  ZCASH_BRANCH_SAPLING,
  type ZcashTxFields,
} from './zcash.js'
import {
  bcsBlake2bMetadata,
  blake2bMetadata,
  emptyMetadata,
  metadataForNamespace,
} from './metadata.js'
import { prepareZcashMessage } from './prepare.js'
import { deriveAddress } from './address.js'

function toHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}
function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}
function u32le(n: number): Uint8Array {
  return Uint8Array.from([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff])
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

const P2PKH = (b: string) => '76a914' + b.repeat(20) + '88ac' // 25-byte P2PKH script

function sampleFields(): ZcashTxFields {
  return {
    inputs: [{ txidHex: 'aa'.repeat(32), vout: 1, sequence: 0xffffffff }],
    outputs: [{ value: 100000n, scriptPubKeyHex: P2PKH('11') }],
    signTarget: { inputIndex: 0, scriptCodeHex: P2PKH('22'), amount: 200000n },
    lockTime: 0,
    expiryHeight: 0,
    branchId: ZCASH_BRANCH_NU5,
    hashType: 1,
  }
}

describe('buildZip243Preimage', () => {
  it('is 294 bytes for a single P2PKH input/output', () => {
    expect(buildZip243Preimage(sampleFields()).length).toBe(294)
  })

  it('starts with the v4 Overwintered header + Sapling version group id', () => {
    const p = buildZip243Preimage(sampleFields())
    expect(toHex(p.slice(0, 4))).toBe('04000080') // 0x80000004 LE
    expect(toHex(p.slice(4, 8))).toBe('85202f89') // 0x892f2085 LE
  })

  it('places the personalized sub-hashes at the ZIP-243 offsets', () => {
    const f = sampleFields()
    const p = buildZip243Preimage(f)
    const prevouts = blake2b(concat(Uint8Array.from(Buffer.from(f.inputs[0]!.txidHex, 'hex')), u32le(f.inputs[0]!.vout)), {
      dkLen: 32,
      personalization: enc('ZcashPrevoutHash'),
    })
    const sequence = blake2b(u32le(0xffffffff), { dkLen: 32, personalization: enc('ZcashSequencHash') })
    const out0 = f.outputs[0]!
    const outScript = Uint8Array.from(Buffer.from(out0.scriptPubKeyHex, 'hex'))
    const outputs = blake2b(
      concat(
        // value u64 LE
        Uint8Array.from([0xa0, 0x86, 0x01, 0, 0, 0, 0, 0]), // 100000
        Uint8Array.from([outScript.length]), // CompactSize (25 < 0xfd)
        outScript,
      ),
      { dkLen: 32, personalization: enc('ZcashOutputsHash') },
    )
    expect(toHex(p.slice(8, 40))).toBe(toHex(prevouts))
    expect(toHex(p.slice(40, 72))).toBe(toHex(sequence))
    expect(toHex(p.slice(72, 104))).toBe(toHex(outputs))
    // joinsplits / shielded spends / shielded outputs are zero (transparent).
    expect(toHex(p.slice(104, 200))).toBe('00'.repeat(96))
    // nHashType = SIGHASH_ALL.
    expect(toHex(p.slice(216, 220))).toBe('01000000')
    // scriptCode CompactSize length byte = 0x19 (25).
    expect(p[256]).toBe(0x19)
  })

  it('is deterministic', () => {
    expect(toHex(buildZip243Preimage(sampleFields()))).toBe(toHex(buildZip243Preimage(sampleFields())))
  })

  it('changes with the consensus branch id only via metadata, not the preimage', () => {
    // branchId lives in the metadata personal, NOT the preimage — so two
    // branch ids yield the SAME preimage.
    const a = buildZip243Preimage({ ...sampleFields(), branchId: ZCASH_BRANCH_NU5 })
    const b = buildZip243Preimage({ ...sampleFields(), branchId: ZCASH_BRANCH_SAPLING })
    expect(toHex(a)).toBe(toHex(b))
  })

  it('rejects empty inputs, bad index, and non-ALL hashType', () => {
    expect(() => buildZip243Preimage({ ...sampleFields(), inputs: [] })).toThrow(RangeError)
    expect(() => buildZip243Preimage({ ...sampleFields(), signTarget: { ...sampleFields().signTarget, inputIndex: 5 } })).toThrow(RangeError)
    expect(() => buildZip243Preimage({ ...sampleFields(), hashType: 0x81 })).toThrow(RangeError)
  })
})

describe('zcashSigHashPersonal', () => {
  it('is 16 bytes: "ZcashSigHash" || branchId LE', () => {
    const p = zcashSigHashPersonal(ZCASH_BRANCH_NU5)
    expect(p.length).toBe(16)
    expect(toHex(p.slice(0, 12))).toBe(toHex(enc('ZcashSigHash')))
    expect(toHex(p.slice(12, 16))).toBe('b4d0d6c2') // 0xc2d6d0b4 LE
  })
})

describe('metadata', () => {
  it('BCS Blake2bMessageMetadata = 0x10 || personal16 || 0x00 (18 bytes)', () => {
    const bcs = bcsBlake2bMetadata(zcashSigHashPersonal(ZCASH_BRANCH_NU5))
    expect(bcs.length).toBe(18)
    expect(bcs[0]).toBe(0x10)
    expect(bcs[17]).toBe(0x00)
  })

  it('blake2bMetadata digest = keccak256(BCS)', () => {
    const md = blake2bMetadata(zcashSigHashPersonal())
    expect(md.ikaMsgMetadataDigest).toEqual(keccak_256(md.metadata))
  })

  it('emptyMetadata is empty bytes + zero digest', () => {
    const md = emptyMetadata()
    expect(md.metadata.length).toBe(0)
    expect(md.ikaMsgMetadataDigest).toEqual(new Uint8Array(32))
  })

  it('metadataForNamespace: zcash non-empty, others empty', () => {
    expect(metadataForNamespace('zcash').metadata.length).toBe(18)
    expect(metadataForNamespace('eip155').metadata.length).toBe(0)
    expect(metadataForNamespace('eip155').ikaMsgMetadataDigest).toEqual(new Uint8Array(32))
  })
})

describe('prepareZcashMessage', () => {
  it('produces preimage + keccak256 digest + non-zero metadata digest', () => {
    const out = prepareZcashMessage('zcash:main', sampleFields())
    expect(out.scheme).toBe(4) // EcdsaBlake2b256
    expect(out.curve).toBe('Secp256k1')
    const preimage = Uint8Array.from(Buffer.from(out.preprocessedHex, 'hex'))
    expect(preimage.length).toBe(294)
    expect(out.digestHex).toBe(toHex(keccak_256(preimage)))
    // metadata digest is keccak256 of the BCS metadata, non-zero.
    expect(out.ikaMsgMetadataDigestHex).not.toBe('00'.repeat(32))
    const md = Uint8Array.from(Buffer.from(out.messageMetadataHex, 'hex'))
    expect(out.ikaMsgMetadataDigestHex).toBe(toHex(keccak_256(md)))
  })

  it('rejects a non-Zcash chain id', () => {
    expect(() => prepareZcashMessage('eip155:1', sampleFields())).toThrow()
  })
})

describe('zcash t-address', () => {
  // Anvil/Hardhat account #0 compressed pubkey (world-known secp256k1 key).
  const PUB = '0x028318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75'
  it('derives a mainnet t1 address (base58check, 0x1cb8 prefix)', () => {
    const addr = deriveAddress(Uint8Array.from(Buffer.from(PUB.slice(2), 'hex')), 'zcash:main')
    expect(addr.startsWith('t1')).toBe(true)
  })
})
