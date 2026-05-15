/**
 * Per-tenant RP_ID / RP_ORIGIN resolution for the passkey flow.
 *
 * Andromeda is a B2D product: each client runs on its own domain
 * (`app.cliente-a.com`, `wallet.cliente-b.io`, …), and WebAuthn binds every
 * passkey to a single RP_ID — there is no "global" RP_ID that would work
 * across clients. The right place to look up which RP_ID/Origin a tenant
 * is allowed to use is the **same** allowlist they already configure on
 * their API key for CORS (`api_keys.allowed_origins`, migration 017).
 *
 * The gateway forwards that list as the `X-Andromeda-Allowed-Origins`
 * header (CSV of `scheme://host[:port]` entries). This module parses it
 * and resolves the `rpId` / `rpOrigin` the client wants to use against
 * the allowlist.
 *
 * Falls back to the env defaults (`config.passkey.rpId/rpOrigin`) only
 * when the key has no allowed_origins — that path covers the Andromeda
 * dashboard itself calling through its own admin key.
 */

import type { Request } from 'express'

const HEADER_ALLOWED_ORIGINS = 'x-andromeda-allowed-origins'

export class OriginNotAllowedError extends Error {
  constructor(
    public readonly requested: string,
    public readonly allowed: string[],
  ) {
    super(`origin not in tenant allowlist: ${requested}`)
    this.name = 'OriginNotAllowedError'
  }
}

export class RpIdNotMatchingOriginError extends Error {
  constructor(
    public readonly rpId: string,
    public readonly origin: string,
  ) {
    super(`rpId '${rpId}' is not a registrable suffix of origin host '${origin}'`)
    this.name = 'RpIdNotMatchingOriginError'
  }
}

export class NoRpConfiguredError extends Error {
  constructor() {
    super(
      'passkey: API key has no allowed_origins and no IKA_PASSKEY_RP_ORIGIN configured — set the allowlist on the key in the dashboard',
    )
    this.name = 'NoRpConfiguredError'
  }
}

/** Parses the gateway-injected CSV; returns `[]` if the header is absent. */
export function parseAllowedOrigins(req: Request): string[] {
  const raw = req.header(HEADER_ALLOWED_ORIGINS)
  if (!raw) return []
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

/** Extracts the host portion of a `scheme://host[:port]` origin (lowercased,
 *  port stripped). Throws if `origin` doesn't parse as a URL. */
export function hostOf(origin: string): string {
  return new URL(origin).hostname.toLowerCase()
}

/**
 * Returns true iff `rpId` is a registrable suffix of `originHost` as defined
 * by WebAuthn §5.1.3 / Public Suffix List rules — i.e. `rpId === originHost`
 * OR `originHost` ends with `'.' + rpId`. This module deliberately does NOT
 * consult the Public Suffix List itself: enforcing that the RP_ID is at
 * least one label below a public suffix is a defense the browser already
 * applies before signing. Here we only enforce the suffix relationship the
 * Andromeda backend can verify offline. The browser is the source of truth
 * for the rest.
 */
export function isRegistrableSuffix(rpId: string, originHost: string): boolean {
  const id = rpId.toLowerCase()
  const host = originHost.toLowerCase()
  if (id === host) return true
  return host.endsWith('.' + id)
}

export interface RpResolution {
  rpId: string
  rpOrigin: string
  /** The full allowlist, propagated to the response of /capabilities. */
  allowedOrigins: string[]
  /** True when we fell back to the env default (dashboard Andromeda path). */
  fallback: boolean
}

export interface ResolveRpInput {
  /** `parseAllowedOrigins(req)` — the per-key allowlist forwarded by the gateway. */
  allowedOrigins: string[]
  /** Optional `rpOrigin` requested by the client. When absent, we pick the first
   *  allowed origin (only safe when the list has exactly one entry). */
  requestedOrigin?: string | undefined
  /** Optional `rpId` requested by the client. When absent, the apex of the
   *  resolved origin is used (e.g. `app.cliente.com` → `cliente.com`). */
  requestedRpId?: string | undefined
  /** Env defaults (config.passkey). Used only when allowedOrigins is empty. */
  envRpOrigin?: string | undefined
  envRpId?: string | undefined
}

/**
 * Resolve `{ rpId, rpOrigin }` for a passkey flow:
 *
 *  1. If the key has `allowed_origins`:
 *     - `rpOrigin` must be one of them (or, if exactly one entry exists,
 *       client may omit and we pick it).
 *     - `rpId` defaults to the registrable apex of `rpOrigin`'s host, but
 *       the client may request a different value as long as it is a
 *       registrable suffix of the host.
 *  2. Otherwise, fall back to the env defaults (Andromeda dashboard path).
 *  3. If neither is available, throw `NoRpConfiguredError`.
 */
export function resolveRp(input: ResolveRpInput): RpResolution {
  const allowed = input.allowedOrigins
  if (allowed.length > 0) {
    let rpOrigin: string
    if (input.requestedOrigin) {
      if (!allowed.includes(input.requestedOrigin)) {
        throw new OriginNotAllowedError(input.requestedOrigin, allowed)
      }
      rpOrigin = input.requestedOrigin
    } else {
      if (allowed.length > 1) {
        throw new Error(
          'rpOrigin required: API key has multiple allowed_origins, client must declare which one',
        )
      }
      rpOrigin = allowed[0]!
    }
    const host = hostOf(rpOrigin)
    const rpId = input.requestedRpId ?? apexOf(host)
    if (!isRegistrableSuffix(rpId, host)) {
      throw new RpIdNotMatchingOriginError(rpId, host)
    }
    return { rpId, rpOrigin, allowedOrigins: allowed, fallback: false }
  }
  if (input.envRpOrigin && input.envRpId) {
    return {
      rpId: input.envRpId,
      rpOrigin: input.envRpOrigin,
      allowedOrigins: [input.envRpOrigin],
      fallback: true,
    }
  }
  throw new NoRpConfiguredError()
}

/**
 * "Apex" heuristic: takes the last two labels of the host as the registrable
 * domain (e.g. `app.cliente.com` → `cliente.com`, `wallet.cliente-b.io` →
 * `cliente-b.io`). This is a pragmatic default — it does NOT consult the
 * Public Suffix List, so `app.cliente.co.uk` resolves to `co.uk` which is
 * wrong. Clients in multi-label-TLD jurisdictions must pass `rpId`
 * explicitly. For `localhost` and bare hostnames, the host itself is the apex.
 */
export function apexOf(host: string): string {
  const labels = host.split('.')
  if (labels.length <= 2) return host
  return labels.slice(-2).join('.')
}
