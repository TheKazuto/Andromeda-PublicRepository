// Minimal CBOR reader — enough to walk a Filecoin `Message` (a CBOR array of
// ints / byte-strings). Tags, floats and indefinite-length items are not needed
// and throw so the caller degrades to "cannot verify".

import { ByteReader } from './bytereader.js'

export type CborValue =
  | bigint
  | Uint8Array
  | string
  | boolean
  | null
  | CborValue[]
  | { [k: string]: CborValue }

function readLength(r: ByteReader, info: number): bigint {
  if (info < 24) return BigInt(info)
  if (info === 24) return BigInt(r.u8())
  if (info === 25) return r.uintBe(2)
  if (info === 26) return r.uintBe(4)
  if (info === 27) return r.uintBe(8)
  throw new Error('unsupported cbor length encoding')
}

function readValue(r: ByteReader): CborValue {
  const b = r.u8()
  const major = b >> 5
  const info = b & 0x1f

  switch (major) {
    case 0: // unsigned int
      return readLength(r, info)
    case 1: // negative int
      return -1n - readLength(r, info)
    case 2: // byte string
      return r.fixed(Number(readLength(r, info)))
    case 3: // text string
      return new TextDecoder().decode(r.fixed(Number(readLength(r, info))))
    case 4: {
      // array
      const len = Number(readLength(r, info))
      const arr: CborValue[] = []
      for (let i = 0; i < len; i += 1) arr.push(readValue(r))
      return arr
    }
    case 5: {
      // map
      const len = Number(readLength(r, info))
      const out: { [k: string]: CborValue } = {}
      for (let i = 0; i < len; i += 1) {
        const k = readValue(r)
        const v = readValue(r)
        if (typeof k === 'string' || typeof k === 'bigint') out[String(k)] = v
      }
      return out
    }
    case 7:
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      throw new Error('unsupported cbor simple value')
    default:
      throw new Error(`unsupported cbor major type ${major}`)
  }
}

/** Parse a single CBOR value from the front of `buf`. Throws on malformed input. */
export function parseCbor(buf: Uint8Array): CborValue {
  return readValue(new ByteReader(buf))
}
