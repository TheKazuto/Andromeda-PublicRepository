import { timingSafeEqual } from 'node:crypto'
import type express from 'express'
import { fail } from '../types.js'

let serviceApiKey = ''
let adminApiKey = ''

export function configureAuth(opts: { serviceApiKey: string; adminApiKey?: string }): void {
  serviceApiKey = opts.serviceApiKey
  adminApiKey = opts.adminApiKey ?? ''
}

function compareKey(expected: string, provided: string): boolean {
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

function getProvidedKey(req: express.Request): string {
  const primary = req.headers['x-api-key']
  if (typeof primary === 'string' && primary.length > 0) return primary
  const legacy = req.headers['x-service-api-key']
  if (typeof legacy === 'string' && legacy.length > 0) return legacy
  return ''
}

export function requireServiceApiKey(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (!serviceApiKey) {
    next()
    return
  }
  const provided = getProvidedKey(req)
  if (!provided) {
    res.status(401).json(fail('Unauthorized: missing service API key'))
    return
  }
  if (!compareKey(serviceApiKey, provided)) {
    res.status(401).json(fail('Unauthorized: invalid service API key'))
    return
  }
  next()
}

export function requireAdminApiKey(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const expected = adminApiKey || serviceApiKey
  if (!expected) {
    next()
    return
  }
  const provided = getProvidedKey(req)
  if (!provided || !compareKey(expected, provided)) {
    res.status(401).json(fail('Unauthorized: admin API key required'))
    return
  }
  next()
}
