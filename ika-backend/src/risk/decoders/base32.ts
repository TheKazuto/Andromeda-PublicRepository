// RFC4648 base32 encoder (no padding). Alphabet is caller-supplied so the same
// routine serves Algorand (uppercase) and Filecoin (lowercase) addresses.

export function base32Encode(data: Uint8Array, alphabet: string): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const b of data) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31]
  }
  return out
}

export const BASE32_RFC4648_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const BASE32_RFC4648_LOWER = 'abcdefghijklmnopqrstuvwxyz234567'
