/**
 * SSRF guard for client-provided RPC URLs.
 *
 * The simulation RPC is supplied by the developer in the request (we don't host
 * RPCs). Since this service runs on a private network alongside sensitive
 * internal services (Vault, Postgres, the other engines), a malicious URL could
 * be used to reach them (Server-Side Request Forgery). Every client RPC URL is
 * validated here before any outbound call:
 *   - scheme must be http/https;
 *   - the host must not be localhost or an internal/reserved name;
 *   - IP literals and every DNS-resolved IP must be public (no loopback,
 *     private, link-local/metadata, CGNAT, ULA, or multicast/reserved range).
 *
 * Residual risk: DNS rebinding (the IP can change between this check and the
 * actual connect). It is partially mitigated by `redirect: 'error'` on the
 * transport (see simulate.ts) and short timeouts; full pinning would require a
 * custom dispatcher and is out of scope for this advisory feature.
 */

import { lookup } from 'node:dns/promises'
import net from 'node:net'

export interface RpcUrlCheck {
  ok: boolean
  reason?: string
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'ip6-localhost', 'ip6-loopback'])

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number(p))
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true
  const [a, b] = parts as [number, number, number, number]
  if (a === 0) return true // "this" network / 0.0.0.0
  if (a === 10) return true // private
  if (a === 127) return true // loopback
  if (a === 169 && b === 254) return true // link-local + cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true // private
  if (a === 192 && b === 168) return true // private
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT (100.64.0.0/10)
  if (a >= 224) return true // multicast (224/4) + reserved (240/4) + broadcast
  return false
}

function isPrivateIpv6(ip: string): boolean {
  const addr = ip.toLowerCase()
  if (addr === '::1' || addr === '::') return true // loopback / unspecified
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/) // IPv4-mapped
  if (mapped) return isPrivateIpv4(mapped[1]!)
  if (addr.startsWith('fc') || addr.startsWith('fd')) return true // ULA fc00::/7 (Railway private)
  if (addr.startsWith('fe8') || addr.startsWith('fe9') || addr.startsWith('fea') || addr.startsWith('feb')) {
    return true // link-local fe80::/10
  }
  return false
}

function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIpv4(ip)
  if (net.isIPv6(ip)) return isPrivateIpv6(ip)
  return true // unknown form → treat as unsafe
}

/**
 * Validate a client-provided RPC URL against SSRF. Resolves DNS for hostnames
 * (IP literals are checked directly). Returns `{ ok: false, reason }` for any
 * unsafe target; never throws.
 */
export async function checkRpcUrl(raw: string): Promise<RpcUrlCheck> {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, reason: 'invalid URL' }
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'protocol must be http or https' }
  }

  const host = url.hostname.toLowerCase()
  if (
    BLOCKED_HOSTNAMES.has(host) ||
    host.endsWith('.internal') ||
    host.endsWith('.local') ||
    host.endsWith('.localhost')
  ) {
    return { ok: false, reason: 'host not allowed' }
  }

  // IP literal: validate directly (no DNS).
  if (net.isIP(host)) {
    return isPrivateIp(host) ? { ok: false, reason: 'private/reserved IP not allowed' } : { ok: true }
  }

  // Hostname: resolve and reject if ANY resolved address is private/reserved.
  let addrs: { address: string }[]
  try {
    addrs = await lookup(host, { all: true })
  } catch {
    return { ok: false, reason: 'DNS resolution failed' }
  }
  if (addrs.length === 0) return { ok: false, reason: 'no DNS records' }
  for (const a of addrs) {
    if (isPrivateIp(a.address)) return { ok: false, reason: 'resolves to a private/reserved IP' }
  }
  return { ok: true }
}
