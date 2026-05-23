// Little-endian byte reader shared by the binary chain decoders (NEAR/Borsh,
// Aptos/BCS, Filecoin/CBOR, Algorand/msgpack). Throws on out-of-bounds reads so
// callers degrade to the honest "cannot verify" path.

export class ByteReader {
  pos = 0
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.pos
  }

  u8(): number {
    const v = this.buf[this.pos]
    if (v === undefined) throw new Error('eof')
    this.pos += 1
    return v
  }

  peek8(): number | undefined {
    return this.buf[this.pos]
  }

  fixed(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) throw new Error('eof')
    const s = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return s
  }

  u16be(): number {
    const b = this.fixed(2)
    return (b[0]! << 8) | b[1]!
  }

  u32le(): number {
    const b = this.fixed(4)
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0
  }

  u32be(): number {
    const b = this.fixed(4)
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0
  }

  uintLe(n: number): bigint {
    const b = this.fixed(n)
    let v = 0n
    for (let i = n - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(b[i]!)
    return v
  }

  uintBe(n: number): bigint {
    const b = this.fixed(n)
    let v = 0n
    for (let i = 0; i < n; i += 1) v = (v << 8n) | BigInt(b[i]!)
    return v
  }

  u64le(): bigint {
    return this.uintLe(8)
  }

  u128le(): bigint {
    return this.uintLe(16)
  }

  /** ULEB128 unsigned varint (BCS lengths / enum discriminants). */
  uleb(): number {
    let result = 0
    let shift = 0
    for (;;) {
      const b = this.u8()
      result |= (b & 0x7f) << shift
      if ((b & 0x80) === 0) break
      shift += 7
      if (shift > 35) throw new Error('uleb overflow')
    }
    return result >>> 0
  }

  /** Borsh string: u32 LE length + UTF-8 bytes. */
  borshString(): string {
    const len = this.u32le()
    return new TextDecoder().decode(this.fixed(len))
  }

  /** BCS string/identifier: ULEB128 length + UTF-8 bytes. */
  bcsString(): string {
    const len = this.uleb()
    return new TextDecoder().decode(this.fixed(len))
  }

  hex(n: number): string {
    return Buffer.from(this.fixed(n)).toString('hex')
  }
}
