// Minimal protobuf wire-format reader — enough to walk Cosmos SDK tx envelopes
// (TxRaw → TxBody → Any) without pulling in a protobuf runtime. Only the wire
// types those envelopes use are supported; anything else throws so the caller
// degrades to "cannot verify".

export interface PbField {
  field: number
  wire: number
  data?: Uint8Array // wire type 2 (length-delimited)
  varint?: bigint // wire type 0
}

function readVarint(buf: Uint8Array, pos: number): { value: bigint; next: number } {
  let result = 0n
  let shift = 0n
  let p = pos
  while (p < buf.length) {
    const b = buf[p]!
    p += 1
    result |= BigInt(b & 0x7f) << shift
    if ((b & 0x80) === 0) return { value: result, next: p }
    shift += 7n
    if (shift > 70n) throw new Error('varint overflow')
  }
  throw new Error('truncated varint')
}

/** Parse one protobuf message into its top-level fields. Throws on malformed input. */
export function parseProtobuf(buf: Uint8Array): PbField[] {
  const out: PbField[] = []
  let pos = 0
  while (pos < buf.length) {
    const tag = readVarint(buf, pos)
    pos = tag.next
    const field = Number(tag.value >> 3n)
    const wire = Number(tag.value & 7n)
    if (field === 0) throw new Error('invalid field number 0')
    switch (wire) {
      case 0: {
        const v = readVarint(buf, pos)
        pos = v.next
        out.push({ field, wire, varint: v.value })
        break
      }
      case 2: {
        const len = readVarint(buf, pos)
        const l = Number(len.value)
        pos = len.next
        if (l < 0 || pos + l > buf.length) throw new Error('truncated length-delimited field')
        out.push({ field, wire, data: buf.subarray(pos, pos + l) })
        pos += l
        break
      }
      case 1:
        pos += 8
        if (pos > buf.length) throw new Error('truncated 64-bit field')
        out.push({ field, wire })
        break
      case 5:
        pos += 4
        if (pos > buf.length) throw new Error('truncated 32-bit field')
        out.push({ field, wire })
        break
      default:
        throw new Error(`unsupported wire type ${wire}`)
    }
  }
  return out
}

/** First field with the given number, or undefined. */
export function firstField(fields: PbField[], n: number): PbField | undefined {
  return fields.find((f) => f.field === n)
}

/** All fields with the given number (repeated proto fields). */
export function allFields(fields: PbField[], n: number): PbField[] {
  return fields.filter((f) => f.field === n)
}
