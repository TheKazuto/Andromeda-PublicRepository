import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { jwsSigningInputDigest } from '../../adapters/solana/oidc.js'

const enc = new TextEncoder()
const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('base64')

describe('oidc/recovery — jwsSigningInputDigest', () => {
  it('digests `header.payload` (everything before the 2nd dot) of a compact JWT', () => {
    const header = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0'
    const payload = 'eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ'
    const signature = 'AAAA-signature-bytes-base64url'
    const jwt = `${header}.${payload}.${signature}`
    const expected = sha256(enc.encode(`${header}.${payload}`))
    expect(Buffer.from(jwsSigningInputDigest(enc.encode(jwt))).toString('base64')).toBe(expected)
  })

  it('only counts the first two dots (a dot inside the b64url signature is fine)', () => {
    // base64url has no '.', but JWS compact serialization splits on the FIRST
    // two dots regardless — verify the helper does the same.
    const a = jwsSigningInputDigest(enc.encode('h.p.sig'))
    const b = jwsSigningInputDigest(enc.encode('h.p.s.i.g'))
    expect(Buffer.from(a).toString('base64')).toBe(Buffer.from(b).toString('base64'))
    expect(Buffer.from(a).toString('base64')).toBe(sha256(enc.encode('h.p')))
  })

  it('rejects a JWT without two `.` separators', () => {
    expect(() => jwsSigningInputDigest(enc.encode('only.one'))).toThrow()
    expect(() => jwsSigningInputDigest(enc.encode('nodots'))).toThrow()
    expect(() => jwsSigningInputDigest(enc.encode(''))).toThrow()
  })

  it('is stable for the same input bytes', () => {
    const jwt = enc.encode('abc.def.ghi')
    expect(Buffer.from(jwsSigningInputDigest(jwt)).toString('base64')).toBe(
      Buffer.from(jwsSigningInputDigest(jwt)).toString('base64'),
    )
  })
})
