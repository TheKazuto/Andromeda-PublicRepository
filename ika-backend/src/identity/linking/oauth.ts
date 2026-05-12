// Account linking — OAuth provider handlers.

import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { canonicalSubject } from '../derive.js'
import { getOauthProvider, OAUTH_PROVIDER_IDS, type OauthProviderId } from '../oauth/providers.js'
import { generateOauthState, generatePkcePair } from '../oauth/pkce.js'
import { consumeOauthState, createOauthState, isOauthStateExpired } from '../oauth/state-store.js'
import { LinkConflictError } from './conflict.js'
import {
  buildIpHash,
  buildLinkResponse,
  persistLinkOrConflict,
  readUserAgent,
  requireAuthedWallet,
} from './common.js'
import type { IdentityRecordData } from '../types.js'

const oauthLinkStartSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  redirectUri: z.string().url().max(2048),
})

const oauthLinkCallbackSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  code: z.string().min(1).max(4096),
  state: z.string().min(1).max(256),
})

export async function handleLinkOauthStart(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = oauthLinkStartSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid OAuth link start payload'))
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
      intent: 'link',
      primaryWalletAddress: wallet,
    })
    const built = await provider.buildAuthorizationUrl({
      state,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
      redirectUri: parsed.data.redirectUri,
    })
    res.json(ok({ authorizationUrl: built.authorizationUrl, state }))
  } catch (err) {
    const sanitized = sanitizeError(`linking.oauth.start.${provider.id}`, err, {
      fallbackMessage: 'Failed to start OAuth link flow',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

export async function handleLinkOauthCallback(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = oauthLinkCallbackSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid OAuth link callback payload'))
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
  if (stateRecord.intent !== 'link' || stateRecord.primaryWalletAddress !== wallet) {
    res.status(400).json(fail('State was not issued for this link flow'))
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

    const subject = canonicalSubject(verified)
    const { persistence } = getIdentityConfig()
    const data: IdentityRecordData = {}
    if (persistence.persistEmail && verified.email) data.email = verified.email
    if (persistence.persistDisplayName && verified.displayName) data.displayName = verified.displayName

    const { alreadyLinked } = await persistLinkOrConflict({
      provider: subject.provider,
      subject: subject.subject,
      primaryWalletAddress: wallet,
      data,
    })
    void recordAuditEvent({
      walletAddress: wallet,
      eventType: 'link.oauth',
      provider: subject.provider,
      metadata: { alreadyLinked, oauthProviderId: provider.id },
      ipHash: buildIpHash(req),
      userAgent: readUserAgent(req),
    })
    res.json(
      ok(
        buildLinkResponse({
          walletAddress: wallet,
          aliasProvider: subject.provider,
          aliasSubject: subject.subject,
          alreadyLinked,
        }),
      ),
    )
  } catch (err) {
    if (err instanceof LinkConflictError) {
      res.status(409).json(fail(err.message))
      return
    }
    const sanitized = sanitizeError(`linking.oauth.callback.${provider.id}`, err, {
      fallbackMessage: 'Failed to complete OAuth link flow',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
