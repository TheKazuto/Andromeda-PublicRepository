// Account linking — email magic-link handlers.

import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { normalizeEmail } from '../derive.js'
import { getEmailTransport } from '../email/transports/index.js'
import { buildMagicLinkUrl, renderMagicLinkEmail } from '../email/templates.js'
import {
  consumeEmailToken,
  createEmailToken,
  generateEmailToken,
  hashEmailToken,
} from '../email/token-store.js'
import { checkEmailRateLimit, hashIpAddress, recordEmailRateHit } from '../email/rate-limit.js'
import { LinkConflictError } from './conflict.js'
import {
  buildIpHash,
  buildLinkResponse,
  persistLinkOrConflict,
  readUserAgent,
  requireAuthedWallet,
} from './common.js'
import type { IdentityRecordData } from '../types.js'

const emailLinkRequestSchema = z.object({
  email: z.string().trim().max(254).email(),
})

const emailLinkVerifySchema = z.object({
  token: z.string().min(1).max(256),
})

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
