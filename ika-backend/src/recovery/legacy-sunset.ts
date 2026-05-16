import { Router, type Request, type Response } from 'express'

/**
 * F11b-Phase3 — legacy `/v1/recovery/*` sunset.
 *
 * The gateway now exposes the equivalent v3 surface at `/v1/policy/*`
 * (PolicyEngine v3: init, add_rule, rule items, request_signature,
 * recover_as_primary, quorum session open/contribute/finalize/close,
 * passkey session open/use/close). Every recovery flow that used to
 * proxy through this ika-backend service is now served in-process by
 * the gateway, with the same auth + idempotency + audit chain.
 *
 * Per Kazuto's decision (2026-05-15): sunset is immediate (410 Gone).
 * Discovery routes (`/v1/recovery/{challenge,resolve}`) stay live —
 * they're the *recovery lookup* surface (find a dwallet given a
 * credential), not a v3-replaceable mutating flow.
 *
 * Headers follow RFC 8594:
 *   - Deprecation: <unix-seconds-of-deprecation>
 *   - Sunset:      <unix-seconds-of-shutdown> (= Deprecation here)
 *   - Link:        <replacement-url>; rel="successor-version"
 *
 * The replacement path is parameterised so each sub-router can point
 * at its closest v3 equivalent. Clients still get a JSON body so the
 * error is machine-readable, not just an opaque 410.
 */

/** Unix timestamp when these routes were marked deprecated AND sunset. */
const SUNSET_UNIX = 1747267200 // 2026-05-15T00:00:00Z

interface SunsetOptions {
  category: 'primary' | 'quorum' | 'policy' | 'oidc' | 'passkey'
  successorPath: string // e.g. "/v1/policy/recover-as-primary/challenge"
  message: string       // human-readable hint for the developer
}

export function buildLegacySunsetRouter(opts: SunsetOptions): Router {
  const router = Router()

  router.use((req: Request, res: Response): void => {
    res.setHeader('Deprecation', `@${SUNSET_UNIX}`)
    res.setHeader('Sunset', new Date(SUNSET_UNIX * 1000).toUTCString())
    res.setHeader('Link', `<${opts.successorPath}>; rel="successor-version"`)
    res.status(410).json({
      error: 'recovery_legacy_sunset',
      message: opts.message,
      sunsetAt: new Date(SUNSET_UNIX * 1000).toISOString(),
      successorPath: opts.successorPath,
      category: opts.category,
      method: req.method,
      path: req.originalUrl,
      doc: 'See PolicyEngine v3 surface under /v1/policy/* on the gateway.',
    })
  })

  return router
}
