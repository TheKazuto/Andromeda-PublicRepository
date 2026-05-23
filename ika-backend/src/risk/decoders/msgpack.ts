// Minimal msgpack reader — enough to walk an Algorand transaction map (string
// keys → ints / byte-strings / nested maps). Unsupported types throw so the
// caller degrades to "cannot verify".

import { ByteReader } from './bytereader.js'

export type MsgpackValue =
  | null
  | boolean
  | bigint
  | string
  | Uint8Array
  | MsgpackValue[]
  | { [k: string]: MsgpackValue }

function readValue(r: ByteReader): MsgpackValue {
  const b = r.u8()

  // positive fixint
  if (b <= 0x7f) return BigInt(b)
  // negative fixint
  if (b >= 0xe0) return BigInt(b - 0x100)
  // fixstr
  if (b >= 0xa0 && b <= 0xbf) return readStr(r, b & 0x1f)
  // fixmap
  if (b >= 0x80 && b <= 0x8f) return readMap(r, b & 0x0f)
  // fixarray
  if (b >= 0x90 && b <= 0x9f) return readArray(r, b & 0x0f)

  switch (b) {
    case 0xc0:
      return null
    case 0xc2:
      return false
    case 0xc3:
      return true
    case 0xcc:
      return BigInt(r.u8())
    case 0xcd:
      return r.uintBe(2)
    case 0xce:
      return r.uintBe(4)
    case 0xcf:
      return r.uintBe(8)
    case 0xd0: {
      const v = r.u8()
      return BigInt(v >= 0x80 ? v - 0x100 : v)
    }
    case 0xd1: {
      const v = Number(r.uintBe(2))
      return BigInt(v >= 0x8000 ? v - 0x10000 : v)
    }
    case 0xd2: {
      const v = Number(r.uintBe(4))
      return BigInt(v >= 0x80000000 ? v - 0x100000000 : v)
    }
    case 0xd3:
      return asSignedBig(r.uintBe(8), 8)
    case 0xc4:
      return r.fixed(r.u8())
    case 0xc5:
      return r.fixed(Number(r.uintBe(2)))
    case 0xc6:
      return r.fixed(Number(r.uintBe(4)))
    case 0xd9:
      return readStr(r, r.u8())
    case 0xda:
      return readStr(r, Number(r.uintBe(2)))
    case 0xdb:
      return readStr(r, Number(r.uintBe(4)))
    case 0xdc:
      return readArray(r, Number(r.uintBe(2)))
    case 0xdd:
      return readArray(r, Number(r.uintBe(4)))
    case 0xde:
      return readMap(r, Number(r.uintBe(2)))
    case 0xdf:
      return readMap(r, Number(r.uintBe(4)))
    default:
      throw new Error(`unsupported msgpack byte 0x${b.toString(16)}`)
  }
}

function asSignedBig(v: bigint, bytes: number): bigint {
  const bits = BigInt(bytes * 8)
  return v >= 1n << (bits - 1n) ? v - (1n << bits) : v
}

function readStr(r: ByteReader, len: number): string {
  return new TextDecoder().decode(r.fixed(len))
}

function readArray(r: ByteReader, len: number): MsgpackValue[] {
  const out: MsgpackValue[] = []
  for (let i = 0; i < len; i += 1) out.push(readValue(r))
  return out
}

function readMap(r: ByteReader, len: number): { [k: string]: MsgpackValue } {
  const out: { [k: string]: MsgpackValue } = {}
  for (let i = 0; i < len; i += 1) {
    const key = readValue(r)
    const val = readValue(r)
    if (typeof key === 'string') out[key] = val
  }
  return out
}

/** Parse a single msgpack value from the front of `buf`. Throws on malformed input. */
export function parseMsgpack(buf: Uint8Array): MsgpackValue {
  return readValue(new ByteReader(buf))
}
