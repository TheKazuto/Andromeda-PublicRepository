/**
 * Minimal Borsh / BCS-style helpers for building Encrypt program instruction data
 * and gRPC payloads. Encrypt program instructions follow the convention:
 *   [discriminator: u8] [args ...]
 *
 * For complex payloads (graph bytes, ReadCiphertextMessage), Encrypt uses BCS.
 * We expose primitive writers below; complex BCS structs should be assembled
 * by the caller in field order matching upstream proto / program code.
 */

export class ByteWriter {
  private chunks: Uint8Array[] = [];
  private size = 0;

  push(bytes: Uint8Array | number[] | number): this {
    if (typeof bytes === 'number') {
      const b = new Uint8Array([bytes & 0xff]);
      this.chunks.push(b);
      this.size += 1;
      return this;
    }
    const arr = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.chunks.push(arr);
    this.size += arr.length;
    return this;
  }

  u8(n: number): this {
    return this.push(n & 0xff);
  }

  u16LE(n: number): this {
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, n, true);
    return this.push(buf);
  }

  u32LE(n: number): this {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, n >>> 0, true);
    return this.push(buf);
  }

  u64LE(n: bigint | number): this {
    const v = typeof n === 'bigint' ? n : BigInt(n);
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, v, true);
    return this.push(buf);
  }

  bytes(arr: Uint8Array): this {
    return this.push(arr);
  }

  // Borsh-style length-prefixed bytes (u32 LE length + bytes)
  vec(arr: Uint8Array): this {
    return this.u32LE(arr.length).bytes(arr);
  }

  build(): Uint8Array {
    const out = new Uint8Array(this.size);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}
