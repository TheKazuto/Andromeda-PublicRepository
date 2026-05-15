import { describe, it, expect } from 'vitest'
import {
  NoRpConfiguredError,
  OriginNotAllowedError,
  RpIdNotMatchingOriginError,
  apexOf,
  hostOf,
  isRegistrableSuffix,
  resolveRp,
} from '../origins.js'

describe('passkey/origins', () => {
  describe('hostOf / apexOf', () => {
    it('strips scheme and port', () => {
      expect(hostOf('https://app.cliente.com:8443')).toBe('app.cliente.com')
    })
    it('lowercases', () => {
      expect(hostOf('https://App.Cliente.COM')).toBe('app.cliente.com')
    })
    it('apexOf returns last two labels', () => {
      expect(apexOf('app.cliente.com')).toBe('cliente.com')
      expect(apexOf('wallet.cliente-b.io')).toBe('cliente-b.io')
    })
    it('apexOf returns the host for short domains', () => {
      expect(apexOf('cliente.com')).toBe('cliente.com')
      expect(apexOf('localhost')).toBe('localhost')
    })
  })

  describe('isRegistrableSuffix', () => {
    it('matches exact', () => {
      expect(isRegistrableSuffix('cliente.com', 'cliente.com')).toBe(true)
    })
    it('matches strict subdomain', () => {
      expect(isRegistrableSuffix('cliente.com', 'app.cliente.com')).toBe(true)
      expect(isRegistrableSuffix('cliente.com', 'a.b.c.cliente.com')).toBe(true)
    })
    it('rejects partial label match', () => {
      // 'liente.com' is NOT a suffix of 'app.cliente.com' (only full labels).
      expect(isRegistrableSuffix('liente.com', 'app.cliente.com')).toBe(false)
    })
    it('rejects unrelated domains', () => {
      expect(isRegistrableSuffix('cliente.com', 'evil.com')).toBe(false)
    })
  })

  describe('resolveRp', () => {
    it('happy path — single allowed origin, derives apex rpId', () => {
      const rp = resolveRp({ allowedOrigins: ['https://app.cliente.com'] })
      expect(rp).toEqual({
        rpId: 'cliente.com',
        rpOrigin: 'https://app.cliente.com',
        allowedOrigins: ['https://app.cliente.com'],
        fallback: false,
      })
    })

    it('client may pick a subdomain rpId as long as it is a suffix of the host', () => {
      const rp = resolveRp({
        allowedOrigins: ['https://app.cliente.com'],
        requestedRpId: 'app.cliente.com',
      })
      expect(rp.rpId).toBe('app.cliente.com')
    })

    it('rejects an rpId that is not a registrable suffix of the origin host', () => {
      expect(() =>
        resolveRp({
          allowedOrigins: ['https://app.cliente.com'],
          requestedRpId: 'evil.com',
        }),
      ).toThrow(RpIdNotMatchingOriginError)
    })

    it('requires explicit rpOrigin when the key has multiple allowed_origins', () => {
      expect(() =>
        resolveRp({
          allowedOrigins: ['https://app.cliente.com', 'https://wallet.cliente.com'],
        }),
      ).toThrow(/rpOrigin required/)
    })

    it('happy path — picks the right origin when multiple allowed', () => {
      const rp = resolveRp({
        allowedOrigins: ['https://app.cliente.com', 'https://wallet.cliente.com'],
        requestedOrigin: 'https://wallet.cliente.com',
      })
      expect(rp.rpOrigin).toBe('https://wallet.cliente.com')
    })

    it('rejects an origin outside the allowlist', () => {
      expect(() =>
        resolveRp({
          allowedOrigins: ['https://app.cliente.com'],
          requestedOrigin: 'https://evil.com',
        }),
      ).toThrow(OriginNotAllowedError)
    })

    it('falls back to env when allowlist is empty (Andromeda dashboard path)', () => {
      const rp = resolveRp({
        allowedOrigins: [],
        envRpOrigin: 'https://app.andromedainfra.pro',
        envRpId: 'andromedainfra.pro',
      })
      expect(rp).toEqual({
        rpId: 'andromedainfra.pro',
        rpOrigin: 'https://app.andromedainfra.pro',
        allowedOrigins: ['https://app.andromedainfra.pro'],
        fallback: true,
      })
    })

    it('throws NoRpConfiguredError when allowlist + env are both absent', () => {
      expect(() => resolveRp({ allowedOrigins: [] })).toThrow(NoRpConfiguredError)
    })
  })
})
