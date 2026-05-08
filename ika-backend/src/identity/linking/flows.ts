// Account linking — handlers.
//
// Each linking endpoint requires a Bearer JWT (the wallet being linked TO
// must already be authenticated). After provider-specific verification, an
// alias row is added to ika_identity_links pointing back to the user's wallet.

import { createHash, randomBytes } from 'node:crypto'
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { canonicalSubject, deriveWalletAddress, normalizeEmail } from '../derive.js'
import { getEmailTransport } from '../email/transports/index.js'
import { buildMagicLinkUrl, renderMagicLinkEmail } from '../email/templates.js'
import {
  consumeEmailToken,
  createEmailToken,
  generateEmailToken,
  hashEmailToken,
} from '../email/token-store.js'
import { checkEmailRateLimit, hashIpAddress, recordEmailRateHit } from '../email/rate-limit.js'
import { getOauthProvider, OAUTH_PROVIDER_IDS, type OauthProviderId } from '../oauth/providers.js'
import { generateOauthState, generatePkcePair } from '../oauth/pkce.js'
import { consumeOauthState, createOauthState, isOauthStateExpired } from '../oauth/state-store.js'
import {
  extractPrfFromClientExtensionResults,
  getPrfSaltBytes,
  PrfNotSupportedError,
} from '../passkey/prf.js'
import {
  consumePasskeyChallenge,
  createPasskeyChallenge,
  upsertIdentityPasskey,
} from '../passkey/store.js'
import {
  createIdentityLink,
  deleteIdentityLink,
  getIdentityLink,
  listIdentityLinksByWallet,
} from '../store.js'
import { evaluateLinkAvailability, LinkConflictError } from './conflict.js'
import type { IdentityProvider, IdentityRecordData } from '../types.js'

const oauthLinkStartSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  redirectUri: z.string().url().max(2048),
})

const oauthLinkCallbackSchema = z.object({
  provider: z.enum(OAUTH_PROVIDER_IDS as [OauthProviderId, ...OauthProviderId[]]),
  code: z.string().min(1).max(4096),
  state: z.string().min(1).max(256),
})

const emailLinkRequestSchema = z.object({
  email: z.string().trim().max(254).email(),
})

const emailLinkVerifySchema = z.object({
  token: z.string().min(1).max(256),
})

const passkeyLinkOptionsSchema = z.object({
  displayName: z.string().min(1).max(120).optional(),
})

const passkeyLinkVerifySchema = z.object({
  attestation: z.unknown(),
  clientExtensionResults: z.unknown().optional(),
  deviceLabel: z.string().min(1).max(120).optional(),
})

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

function requireAuthedWallet(req: Request, res: Response): string | null {
  const wallet = req.userWalletAddress
  if (!wallet) {
    res.status(401).json(fail('Unauthorized'))
    return null
  }
  return wallet
}

function buildLinkResponse(args: {
  walletAddress: string
  aliasProvider: IdentityProvider
  aliasSubject: string
  alreadyLinked: boolean
}) {
  return {
    walletAddress: args.walletAddress,
    linkedProvider: args.aliasProvider,
    linkedSubject: args.aliasSubject,
    alreadyLinked: args.alreadyLinked,
  }
}

async function persistLinkOrConflict(args: {
  provider: IdentityProvider
  subject: string
  primaryWalletAddress: string
  data?: IdentityRecordData
}): Promise<{ alreadyLinked: boolean }> {
  const availability = await evaluateLinkAvailability(args.provider, args.subject, args.primaryWalletAddress)
  if (availability.state === 'conflict-primary' || availability.state === 'conflict-alias') {
    throw new LinkConflictError(
      'This identity is already associated with another wallet. Sign in with that account first if you want to migrate.',
      availability.state,
    )
  }
  if (availability.state === 'already-linked-to-self') {
    return { alreadyLinked: true }
  }
  await createIdentityLink({
    aliasProvider: args.provider,
    aliasSubject: args.subject,
    primaryWalletAddress: args.primaryWalletAddress,
    data: args.data ?? {},
  })
  return { alreadyLinked: false }
}

// ── OAuth linking ──────────────────────────────────────────────────

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

// ── Email linking ──────────────────────────────────────────────────

export async function handleLinkEmailRequest(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const okResponse = () => res.json(ok({ success: true }))

  const parsed = emailLinkRequestSchema.safeParse(req.body)
  if (!parsed.success) {
    okResponse()
    return
  }

  const config = getIdentityConfig()
  if (!config.providers.email || !config.email.frontendCallbackUrl) {
    okResponse()
    return
  }

  const email = normalizeEmail(parsed.data.email)
  const ip = req.ip || req.socket?.remoteAddress || null
  const ipHash = ip ? hashIpAddress(ip) : null

  try {
    const decision = await checkEmailRateLimit({
      email,
      ipHash,
      limitPerEmail: config.email.rateLimitPerEmailPerHour,
      limitPerIp: config.email.rateLimitPerIpPerHour,
    })
    if (!decision.allowed) {
      okResponse()
      return
    }

    const generated = generateEmailToken()
    await createEmailToken({
      tokenHash: generated.tokenHash,
      email,
      intent: 'link',
      primaryWalletAddress: wallet,
      ttlSeconds: config.email.tokenTtlSeconds,
    })
    await recordEmailRateHit(email, ipHash)

    const link = buildMagicLinkUrl(config.email.frontendCallbackUrl, generated.token)
    const ttlMinutes = Math.max(1, Math.round(config.email.tokenTtlSeconds / 60))
    const rendered = renderMagicLinkEmail({ intent: 'link', link, ttlMinutes })
    await getEmailTransport().send({
      to: email,
      subject: rendered.subject,
      html: rendered.html,
      text: rendered.text,
    })
  } catch (err) {
    sanitizeError('linking.email.request', err, { fallbackMessage: 'email link request failed' })
  }
  okResponse()
}

export async function handleLinkEmailVerify(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = emailLinkVerifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid magic link token'))
    return
  }
  try {
    const tokenHash = hashEmailToken(parsed.data.token)
    const record = await consumeEmailToken(tokenHash)
    if (!record) {
      res.status(400).json(fail('Magic link is invalid or already used'))
      return
    }
    if (record.intent !== 'link' || record.primaryWalletAddress !== wallet) {
      res.status(400).json(fail('Magic link is not a link-flow token for this wallet'))
      return
    }

    const { persistence } = getIdentityConfig()
    const data: IdentityRecordData = persistence.persistEmail ? { email: record.email } : {}

    const { alreadyLinked } = await persistLinkOrConflict({
      provider: 'email',
      subject: record.email,
      primaryWalletAddress: wallet,
      data,
    })
    void recordAuditEvent({
      walletAddress: wallet,
      eventType: 'link.email',
      provider: 'email',
      metadata: { alreadyLinked },
      ipHash: buildIpHash(req),
      userAgent: readUserAgent(req),
    })
    res.json(
      ok(
        buildLinkResponse({
          walletAddress: wallet,
          aliasProvider: 'email',
          aliasSubject: record.email,
          alreadyLinked,
        }),
      ),
    )
  } catch (err) {
    if (err instanceof LinkConflictError) {
      res.status(409).json(fail(err.message))
      return
    }
    const sanitized = sanitizeError('linking.email.verify', err, {
      fallbackMessage: 'Failed to verify magic link',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

// ── Passkey linking ───────────────────────────────────────────────

const PASSKEY_LINK_CHALLENGE_TTL_MS = 5 * 60 * 1000

interface AttestationLike {
  response?: { clientDataJSON?: string; transports?: string[] }
  clientExtensionResults?: unknown
}

function readChallengeFromAttestation(attestation: unknown): string | null {
  const att = attestation as AttestationLike
  const clientDataJSON = att?.response?.clientDataJSON
  if (typeof clientDataJSON !== 'string') return null
  try {
    const decoded = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8')) as {
      challenge?: string
    }
    return typeof decoded.challenge === 'string' ? decoded.challenge : null
  } catch {
    return null
  }
}

export async function handleLinkPasskeyRegisterOptions(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = passkeyLinkOptionsSchema.safeParse(req.body ?? {})
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey link options payload'))
    return
  }
  try {
    const config = getIdentityConfig()
    if (!config.passkey.rpId || config.passkey.origins.length === 0) {
      res.status(400).json(fail('Passkey identity is not configured'))
      return
    }
    const userHandle = randomBytes(16).toString('base64url')
    const options = await generateRegistrationOptions({
      rpID: config.passkey.rpId,
      rpName: config.passkey.rpName ?? 'Andromeda',
      userID: Buffer.from(userHandle, 'utf8'),
      userName: parsed.data.displayName ?? userHandle,
      userDisplayName: parsed.data.displayName ?? 'Andromeda user',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      extensions: { prf: { eval: { first: getPrfSaltBytes() } } } as unknown as never,
    })
    await createPasskeyChallenge({
      challenge: options.challenge,
      type: 'registration',
      ttlMs: PASSKEY_LINK_CHALLENGE_TTL_MS,
      userHandle,
      targetWalletAddress: wallet,
      metadata: { intent: 'link', displayName: parsed.data.displayName ?? null },
    })
    res.json(ok(options))
  } catch (err) {
    const sanitized = sanitizeError('linking.passkey.options', err, {
      fallbackMessage: 'Failed to generate passkey registration options',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

export async function handleLinkPasskeyRegisterVerify(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return
  const parsed = passkeyLinkVerifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid passkey link verify payload'))
    return
  }
  try {
    const config = getIdentityConfig()
    if (!config.passkey.rpId || config.passkey.origins.length === 0) {
      res.status(400).json(fail('Passkey identity is not configured'))
      return
    }
    const challenge = readChallengeFromAttestation(parsed.data.attestation)
    if (!challenge) {
      res.status(400).json(fail('Attestation is missing or malformed'))
      return
    }
    const challengeRecord = await consumePasskeyChallenge(challenge, 'registration')
    if (!challengeRecord) {
      res.status(400).json(fail('Registration challenge is invalid or expired'))
      return
    }
    if (challengeRecord.targetWalletAddress !== wallet) {
      res.status(400).json(fail('Challenge was not issued for this wallet'))
      return
    }
    const verification = await verifyRegistrationResponse({
      response: parsed.data.attestation as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: challengeRecord.challenge,
      expectedOrigin: config.passkey.origins,
      expectedRPID: config.passkey.rpId,
      requireUserVerification: false,
    })
    if (!verification.verified || !verification.registrationInfo) {
      res.status(400).json(fail('Registration verification failed'))
      return
    }

    const clientExt = (parsed.data.clientExtensionResults
      ?? (parsed.data.attestation as AttestationLike)?.clientExtensionResults) as unknown
    let prfHex: string
    try {
      prfHex = extractPrfFromClientExtensionResults(clientExt)
    } catch (err) {
      const message =
        err instanceof PrfNotSupportedError ? err.message : 'PRF output could not be read from this device'
      res.status(400).json(fail(message))
      return
    }

    const passkeyDerivedWallet = deriveWalletAddress({ provider: 'passkey-prf', prfOutputHex: prfHex })
    const credentialId = verification.registrationInfo.credential.id
    const publicKeyBase64 = Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64')
    const counter = verification.registrationInfo.credential.counter ?? 0
    const transports =
      parsed.data.attestation &&
      typeof parsed.data.attestation === 'object' &&
      Array.isArray((parsed.data.attestation as AttestationLike).response?.transports)
        ? ((parsed.data.attestation as AttestationLike).response!.transports as string[])
        : null

    try {
      await upsertIdentityPasskey({
        credentialId,
        walletAddress: passkeyDerivedWallet,
        publicKeyBase64,
        counter,
        transports,
        deviceLabel: parsed.data.deviceLabel ?? null,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey credential conflict'
      res.status(409).json(fail(message))
      return
    }

    const { alreadyLinked } = await persistLinkOrConflict({
      provider: 'passkey-prf',
      subject: prfHex,
      primaryWalletAddress: wallet,
    })
    void recordAuditEvent({
      walletAddress: wallet,
      eventType: 'link.passkey',
      provider: 'passkey-prf',
      metadata: { alreadyLinked, credentialId },
      ipHash: buildIpHash(req),
      userAgent: readUserAgent(req),
    })
    res.json(
      ok({
        ...buildLinkResponse({
          walletAddress: wallet,
          aliasProvider: 'passkey-prf',
          aliasSubject: prfHex,
          alreadyLinked,
        }),
        credentialId,
      }),
    )
  } catch (err) {
    if (err instanceof LinkConflictError) {
      res.status(409).json(fail(err.message))
      return
    }
    const sanitized = sanitizeError('linking.passkey.verify', err, {
      fallbackMessage: 'Passkey link failed',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}

// ── DELETE link ───────────────────────────────────────────────────

const VALID_PROVIDER_PARAMS: ReadonlyArray<IdentityProvider> = [
  'oauth-google',
  'oauth-apple',
  'oauth-twitter',
  'oauth-github',
  'email',
  'passkey-prf',
] as const

function isValidProviderParam(value: string): value is IdentityProvider {
  return (VALID_PROVIDER_PARAMS as ReadonlyArray<string>).includes(value)
}

export async function handleDeleteLink(req: Request, res: Response): Promise<void> {
  const wallet = requireAuthedWallet(req, res)
  if (!wallet) return

  const providerParam = typeof req.params.provider === 'string' ? req.params.provider : ''
  const subjectParam = typeof req.params.subject === 'string' ? decodeURIComponent(req.params.subject) : ''

  if (!isValidProviderParam(providerParam)) {
    res.status(400).json(fail('Invalid provider'))
    return
  }
  if (!subjectParam) {
    res.status(400).json(fail('Invalid subject'))
    return
  }

  try {
    const link = await getIdentityLink(providerParam, subjectParam)
    if (!link) {
      res.status(404).json(fail('Link not found'))
      return
    }
    if (link.primaryWalletAddress !== wallet) {
      res.status(403).json(fail('Cannot remove a link belonging to another wallet'))
      return
    }
    const remaining = await listIdentityLinksByWallet(wallet)
    if (remaining.length === 0) {
      res.status(500).json(fail('Inconsistent link state'))
      return
    }
    const removed = await deleteIdentityLink(providerParam, subjectParam)
    void recordAuditEvent({
      walletAddress: wallet,
      eventType: 'unlink',
      provider: providerParam,
      metadata: { subject: subjectParam },
      ipHash: buildIpHash(req),
      userAgent: readUserAgent(req),
    })
    res.json(ok({ success: removed }))
  } catch (err) {
    const sanitized = sanitizeError('linking.delete', err, {
      fallbackMessage: 'Failed to remove link',
    })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
