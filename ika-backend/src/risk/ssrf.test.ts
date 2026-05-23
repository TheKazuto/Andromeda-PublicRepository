/**
 * Tests for the SSRF guard on client-provided RPC URLs. Uses IP literals and
 * blocked hostnames so no real DNS/network is touched.
 */

import { describe, it, expect } from 'vitest'
import { checkRpcUrl } from './ssrf.js'

describe('checkRpcUrl', () => {
  it('accepts a public IPv4 literal', async () => {
    expect(await checkRpcUrl('http://1.2.3.4:8545')).toEqual({ ok: true })
    expect((await checkRpcUrl('https://8.8.8.8')).ok).toBe(true)
  })

  it('rejects loopback and private IPv4 ranges', async () => {
    expect((await checkRpcUrl('http://127.0.0.1:8545')).ok).toBe(false)
    expect((await checkRpcUrl('http://10.0.0.5')).ok).toBe(false)
    expect((await checkRpcUrl('http://192.168.1.1')).ok).toBe(false)
    expect((await checkRpcUrl('http://172.16.0.1')).ok).toBe(false)
    expect((await checkRpcUrl('http://100.64.0.1')).ok).toBe(false)
  })

  it('rejects the cloud metadata endpoint (link-local)', async () => {
    expect((await checkRpcUrl('http://169.254.169.254/latest/meta-data')).ok).toBe(false)
  })

  it('rejects loopback and ULA/link-local IPv6', async () => {
    expect((await checkRpcUrl('http://[::1]:8545')).ok).toBe(false)
    expect((await checkRpcUrl('http://[fd00::1]')).ok).toBe(false)
    expect((await checkRpcUrl('http://[fe80::1]')).ok).toBe(false)
  })

  it('rejects IPv4-mapped IPv6 pointing at a private address', async () => {
    expect((await checkRpcUrl('http://[::ffff:127.0.0.1]')).ok).toBe(false)
  })

  it('rejects localhost and internal hostnames without DNS', async () => {
    expect((await checkRpcUrl('http://localhost:8545')).ok).toBe(false)
    expect((await checkRpcUrl('http://vault.railway.internal')).ok).toBe(false)
    expect((await checkRpcUrl('http://db.internal')).ok).toBe(false)
  })

  it('rejects non-http(s) protocols and malformed URLs', async () => {
    expect((await checkRpcUrl('ftp://1.2.3.4')).ok).toBe(false)
    expect((await checkRpcUrl('file:///etc/passwd')).ok).toBe(false)
    expect((await checkRpcUrl('not a url')).ok).toBe(false)
  })
})
