// Identity layer — dual-mode authentication middleware.
//
// Service mode: caller passes X-Api-Key. body.address remains authoritative.
// User mode:    caller passes Authorization: Bearer <productJwt>.
//   Wallet address is extracted from JWT subject and OVERRIDES body.address.

import { timingSafeEqual } from 'node:crypto'
import type { NextFunction, Request, Response } from 'express'
import { fail } from '../types.js'
import { InvalidProductJwtError, verifyProductJwt } from './jwt.js'

function readServiceApiKey(): string {
  return process.env.INTERNAL_API_KEY?.trim() ?? ''
}

function timingSafeEqualString(expected: string, provided: string): boolean {
  if (!expected || !provided) return false
  const a = Buffer.from(expected, 'utf8')
  const b = Buffer.from(provided, 'utf8')
  if (a.length !== b.length) return false
  try {
    return timingSafeEqual(a, b)
  } catch {
    return false
  }
}

function readApiKeyHeader(req: Request): string {
  const primary = req.headers['x-api-key']
  if (typeof primary === 'string' && primary.length > 0) return primary
  const legacy = req.headers['x-service-api-key']
  if (typeof legacy === 'string' && legacy.length > 0) return legacy
  return ''
}

function readBearerToken(req: Request): string | null {
  const header = req.headers.authorization
  if (typeof header !== 'string') return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  if (!match) return null
  const token = match[1]!.trim()
  return token.length > 0 ? token : null
}

export async function requireUserOrServiceAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const serviceKey = readServiceApiKey()
  const providedKey = readApiKeyHeader(req)

  if (providedKey && serviceKey && timingSafeEqualString(serviceKey, providedKey)) {
    req.authMode = 'service'
    next()
    return
  }

  const bearer = readBearerToken(req)
  if (bearer) {
    try {
      const payload = await verifyProductJwt(bearer)
      req.authMode = 'user'
      req.userWalletAddress = payload.sub
      req.userProvider = payload.provider
      req.userPrimaryProvider = payload.primaryProvider
      req.userJwtId = payload.jti
      next()
      return
    } catch (err) {
      const message = err instanceof InvalidProductJwtError ? err.message : 'Invalid product JWT'
      res.status(401).json(fail(message))
      return
    }
  }

  res.status(401).json(fail('Unauthorized: missing X-Api-Key or Bearer token'))
}

export async function requireUserAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const bearer = readBearerToken(req)
  if (!bearer) {
    res.status(401).json(fail('Unauthorized: missing Bearer token'))
    return
  }
  try {
    const payload = await verifyProductJwt(bearer)
    req.authMode = 'user'
    req.userWalletAddress = payload.sub
    req.userProvider = payload.provider
    req.userPrimaryProvider = payload.primaryProvider
    req.userJwtId = payload.jti
    next()
  } catch (err) {
    const message = err instanceof InvalidProductJwtError ? err.message : 'Invalid product JWT'
    res.status(401).json(fail(message))
  }
}

export function getAuthorizedWalletAddress(req: Request): string | null {
  if (req.authMode === 'user') {
    return req.userWalletAddress ?? null
  }
  if (req.authMode === 'service') {
    const body = req.body as { address?: unknown; ownerAddress?: unknown } | undefined
    if (typeof body?.address === 'string' && body.address.length > 0) return body.address
    if (typeof body?.ownerAddress === 'string' && body.ownerAddress.length > 0) return body.ownerAddress
    return null
  }
  return null
}
