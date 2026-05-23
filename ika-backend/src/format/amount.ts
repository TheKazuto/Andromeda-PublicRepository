// Human-readable amount formatting (display-only).
//
// Renders a raw integer amount (base units) as a decimal string by shifting it
// `decimals` places: formatAmount(1500000000n, 9) === "1.5". Trailing zeros in
// the fraction are trimmed; an exact integer has no decimal point.
//
// Ported from clear-msig `programs/clear-wallet/src/utils/message.rs`
// (`push_decimal_u64`). The PLAIN output (`formatAmountPlain`, no opts) is the
// canonical decimal-shift shared byte-for-byte with the gateway (Go) and the
// on-chain challenge templates (Rust) that render signed human messages — do
// NOT change its shape without updating those mirrors + fixtures (Update 6 M2).
//
// `opts` (group separator, symbol) are display-only decorations that NEVER enter
// any signed message, challenge, or hash. They exist purely to help the dev
// render the value in their own UI consistently with what the user signs.

/** Max decimals supported — u128 base units fit in ≤ 39 digits. */
export const MAX_DECIMALS = 38

export interface FormatAmountOptions {
  /** Append " <symbol>" (e.g. "USD", "ETH"). Display-only, never signed. */
  symbol?: string
  /** Group the integer part with ',' every 3 digits (en locale). Display-only. */
  group?: boolean
}

/**
 * Canonical plain decimal shift (mirror of `push_decimal_u64`). `raw` must be
 * a non-negative integer amount in base units.
 * @throws {RangeError} on negative `raw` or out-of-range `decimals`.
 */
export function formatAmountPlain(raw: bigint, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > MAX_DECIMALS) {
    throw new RangeError(`decimals must be an integer in [0, ${MAX_DECIMALS}]`)
  }
  if (raw < 0n) throw new RangeError('raw must be non-negative')
  if (decimals === 0) return raw.toString()

  const scale = 10n ** BigInt(decimals)
  const intPart = raw / scale
  const frac = raw % scale
  if (frac === 0n) return intPart.toString()

  // Zero-pad the fraction to `decimals` digits, then trim trailing zeros.
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${intPart.toString()}.${fracStr}`
}

/** Insert ',' every 3 digits from the right of an all-digits string. */
function groupInteger(intStr: string): string {
  return intStr.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

/**
 * Display-only formatter. The plain decimal shift is canonical; `opts` add
 * presentation-only decoration that is never part of a signed message.
 * @throws {RangeError} via {@link formatAmountPlain}.
 */
export function formatAmount(raw: bigint, decimals: number, opts: FormatAmountOptions = {}): string {
  let s = formatAmountPlain(raw, decimals)
  if (opts.group) {
    const dot = s.indexOf('.')
    s = dot === -1 ? groupInteger(s) : groupInteger(s.slice(0, dot)) + s.slice(dot)
  }
  if (opts.symbol) s = `${s} ${opts.symbol}`
  return s
}
