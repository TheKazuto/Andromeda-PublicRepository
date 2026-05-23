import { describe, expect, it } from 'vitest'
import { formatAmount, formatAmountPlain, MAX_DECIMALS } from './amount.js'

describe('formatAmountPlain — canonical decimal shift', () => {
  const cases: Array<[bigint, number, string]> = [
    [0n, 9, '0'],
    [0n, 0, '0'],
    [1500000000n, 9, '1.5'],
    [1000000000n, 9, '1'], // exact integer → no decimal point
    [1n, 9, '0.000000001'], // smallest unit
    [123456789n, 8, '1.23456789'],
    [300000000000n, 8, '3000'], // $3,000 at 1e8 → integer
    [300050000000n, 8, '3000.5'], // $3,000.50 at 1e8 → trailing zeros trimmed
    [1234567n, 0, '1234567'], // decimals=0 → raw as-is
    [100n, 2, '1'],
    [101n, 2, '1.01'],
    [110n, 2, '1.1'],
    // u128-scale value (well beyond u64)
    [123456789012345678901234567890n, 18, '123456789012.34567890123456789'],
  ]
  for (const [raw, decimals, expected] of cases) {
    it(`formatAmountPlain(${raw}n, ${decimals}) === "${expected}"`, () => {
      expect(formatAmountPlain(raw, decimals)).toBe(expected)
    })
  }

  it('rejects negative raw', () => {
    expect(() => formatAmountPlain(-1n, 9)).toThrow(RangeError)
  })
  it('rejects out-of-range decimals', () => {
    expect(() => formatAmountPlain(1n, -1)).toThrow(RangeError)
    expect(() => formatAmountPlain(1n, MAX_DECIMALS + 1)).toThrow(RangeError)
    expect(() => formatAmountPlain(1n, 1.5)).toThrow(RangeError)
  })
})

describe('formatAmount — display-only decoration', () => {
  it('groups the integer part', () => {
    expect(formatAmount(300000000000n, 8, { group: true })).toBe('3,000')
    expect(formatAmount(123456789012345n, 8, { group: true })).toBe('1,234,567.89012345')
    expect(formatAmount(999n, 0, { group: true })).toBe('999')
    expect(formatAmount(1000n, 0, { group: true })).toBe('1,000')
  })
  it('appends a symbol', () => {
    expect(formatAmount(1500000000n, 9, { symbol: 'ETH' })).toBe('1.5 ETH')
    expect(formatAmount(300050000000n, 8, { symbol: 'USD', group: true })).toBe('3,000.5 USD')
  })
  it('with no opts equals the plain shift', () => {
    expect(formatAmount(1500000000n, 9)).toBe(formatAmountPlain(1500000000n, 9))
  })
})
