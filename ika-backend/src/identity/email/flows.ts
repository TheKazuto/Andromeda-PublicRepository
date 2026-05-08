// Email — magic link request + verify handlers.
//
// Anti-enumeration: /email/request always returns 200 OK regardless of
// outcome (rate-limited, transport failure, malformed input). Failures
// still get logged server-side under a trace id so ops can diagnose.
//
// Single-use: /email/verify atomically consumes the token via gated UPDATE.

import { createHash } from 'node:crypto'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { logger } from '../../logger.js'
import { recordAuditEvent } from '../audit.js'
import { getIdentityConfig } from '../config.js'
import { normalizeEmail } from '../derive.js'
import { createSessionForIdentity, type IdentitySession } from '../session.js'
import { consumeEmailRateLimit, hashIpAddress } from './rate-limit.js'
import { buildMagicLinkUrl, renderMagicLinkEmail } from './templates.js'
import {
  consumeEmailToken,
  createEmailToken,
  generateEmailToken,
  hashEmailToken,
} from './token-store.js'
import { getEmailTransport } from './transports/index.js'

const requestSchema = z.object({
  email: z.string().trim().max(254).email(),
})

const verifySchema = z.object({
  token: z.string().min(1).max(256),
})

function readUserAgent(req: Request): string | null {
  const ua = req.headers['user-agent']
  if (typeof ua !== 'string' || ua.length === 0) return null
  return ua.length > 512 ? ua.slice(0, 512) : ua
}

function buildIpHash(req: Request): string | null {
  const ip = req.ip || req.socket?.remoteAddress
  if (!ip) return null
  return createHash('sha256').update(ip).digest('hex').slice(0, 32)
}

export async function handleEmailRequest(req: Request, res: Response): Promise<void> {
  const okResponse = () => res.json(ok({ success: true }))

  const parsed = requestSchema.safeParse(req.body)
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
    const decision = await consumeEmailRateLimit({
      email,
      ipHash,
      limitPerEmail: config.email.rateLimitPerEmailPerHour,
      limitPerIp: config.email.rateLimitPerIpPerHour,
    })
    if (!decision.allowed) {
      logger.warn(
        { reason: decision.reason, emailHash: hashEmailToken(email).slice(0, 16), ipHash },
        'identity/email rate-limited',
      )
      okResponse()
      return
    }

    const generated = generateEmailToken()
    await createEmailToken({
      tokenHash: generated.tokenHash,
      email,
      intent: 'login',
      ttlSeconds: config.email.tokenTtlSeconds,
    })
    const link = buildMagicLinkUrl(config.email.frontendCallbackUrl, generated.token)
    const ttlMinutes = Math.max(1, Math.round(config.email.tokenTtlSeconds / 60))
    const rendered = renderMagicLinkEmail({ intent: 'login', link, ttlMinutes })

    await getEmailTransport().send({
      to: email,
      subject: rendered.subject,
      html: rendered.html,
      text: rendered.text,
    })
  } catch (err) {
    sanitizeError('email.request', err, { fallbackMessage: 'email request failed' })
  }

  okResponse()
}

export async function handleEmailVerify(req: Request, res: Response): Promise<void> {
  const parsed = verifySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json(fail('Invalid magic link token'))
    return
  }

  const config = getIdentityConfig()
  if (!config.providers.email) {
    res.status(404).json(fail('Email login is not enabled'))
    return
  }

  const tokenHash = hashEmailToken(parsed.data.token)
  const record = await consumeEmailToken(tokenHash)
  if (!record) {
    res.status(400).json(fail('Magic link is invalid or already used'))
    return
  }
  if (record.intent !== 'login') {
    res.status(400).json(fail('Magic link is not a login link'))
    return
  }

  try {
    const ipHash = buildIpHash(req)
    const userAgent = readUserAgent(req)
    const session: IdentitySession = await createSessionForIdentity(
      { provider: 'email', email: record.email },
      { ipHash, userAgent },
    )
    void recordAuditEvent({
      walletAddress: session.walletAddress,
      eventType: 'login.email',
      provider: 'email',
      metadata: { isNew: session.isNew },
      ipHash,
      userAgent,
    })
    res.json(ok(session))
  } catch (err) {
    const sanitized = sanitizeError('email.verify', err, { fallbackMessage: 'Failed to verify magic link' })
    res.status(500).json(fail(sanitized.message, sanitized.traceId))
  }
}
