// OAuth — generic start + callback handlers (provider-agnostic).

import { createHash } from 'node:crypto'
import { z } from 'zod'
import type { Request, Response } from 'express'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { createSessionForIdentity, type IdentitySession } from '../session.js'
import { getOauthProvider, type OauthProviderId, OAUTH_PROVIDER_IDS } from './providers.js'
import { generateOauthState, generatePkcePair } from './pkce.js'
import { consumeOauthState, createOauthState, isOauthStateExpired } from './state-store.js'

const startSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  redirectUri: z.string().url().max(2048),
})

const callbackSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  code: z.string().min(1).max(4096),
  state: z.string().min(1).max(256),
})

export interface StartOauthResult {
  authorizationUrl: string
  state: string
}

function buildIpHash(req: Request): string | null {
  const ip = req.ip || req.socket?.remoteAddress
  if (!ip) return null
  return createHash('sha256').update(ip).digest('hex').slice(0, 32)
}

function readUserAgent(req: Request): string | null {
  const ua = req.headers['user-agent']
  if (typeof ua !== 'string' || ua.length === 0) return null
  return ua.length > 512 ? ua.slice(0, 512) : ua
}

export async function handleOauthStart(req: Request, res: Response): Promise<void> {
  const parsed = startSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid OAuth start payload'))
    return
  }
  const provider = getOauthProvider(parsed.data.provider)
  if (!provider || !provider.isEnabled()) {
    res.status(400).json(fail(`OAuth provider ${parsed.data.provider} is not enabled`))
    return
  }
  if (!provider.isAllowedRedirectUri(parsed.data.redirectUri)) {
    res.status(400).json(fail('redirectUri is not on the provider whitelist'))
    return
  }

  try {
    const state = generateOauthState()
    const pkce = generatePkcePair()
    await createOauthState({
      state,
      provider: provider.id,
      codeVerifier: pkce.codeVerifier,
      redirectUri: parsed.data.redirectUri,
      intent: 'login',
    })
    const built = await provider.buildAuthorizationUrl({
      state,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
      redirectUri: parsed.data.redirectUri,
    })
    res.json(ok<StartOauthResult>({ authorizationUrl: built.authorizationUrl, state }))
  } catch (err) {
    const sanitized = sanitizeError(`oauth.start.${provider.id}`, err, {
      fallbackMessage: 'Failed to start OAuth flow',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

export async function handleOauthCallback(req: Request, res: Response): Promise<void> {
  const parsed = callbackSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid OAuth callback payload'))
    return
  }
  const provider = getOauthProvider(parsed.data.provider)
  if (!provider || !provider.isEnabled()) {
    res.status(400).json(fail(`OAuth provider ${parsed.data.provider} is not enabled`))
    return
  }

  const stateRecord = await consumeOauthState(parsed.data.state)
  if (!stateRecord) {
    res.status(400).json(fail('Invalid or already-used state'))
    return
  }
  if (stateRecord.provider !== provider.id) {
    res.status(400).json(fail('State/provider mismatch'))
    return
  }
  if (isOauthStateExpired(stateRecord)) {
    res.status(400).json(fail('State has expired'))
    return
  }

  try {
    const verified = await provider.exchangeAndVerify({
      code: parsed.data.code,
      codeVerifier: stateRecord.codeVerifier,
      redirectUri: stateRecord.redirectUri,
    })

    const ipHash = buildIpHash(req)
    const userAgent = readUserAgent(req)
    const session = await createSessionForIdentity(verified, { ipHash, userAgent })

    void recordAuditEvent({
      walletAddress: session.walletAddress,
      eventType: 'login.oauth',
      provider: verified.provider,
      metadata: { isNew: session.isNew, oauthProviderId: provider.id },
      ipHash,
      userAgent,
    })

    res.json(ok<IdentitySession>(session))
  } catch (err) {
    const sanitized = sanitizeError(`oauth.callback.${provider.id}`, err, {
      fallbackMessage: 'Failed to complete OAuth flow',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
