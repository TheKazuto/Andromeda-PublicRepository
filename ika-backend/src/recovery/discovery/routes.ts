import { Router } from 'express'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import {
  buildChallenge,
  challengeRequestSchema,
  resolveChallenge,
  resolveRequestSchema,
} from './flows.js'
import type { AppConfig } from '../../config.js'

export function buildDiscoveryRouter(config: AppConfig): Router {
  const router = Router()

  router.post('/challenge', async (req, res) => {
    try {
      const parsed = challengeRequestSchema.parse(req.body)
      const result = await buildChallenge(parsed, config)
      res.json(ok(result))
    } catch (err) {
      const safe = sanitizeError('recovery/discovery/challenge', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/resolve', async (req, res) => {
    try {
      const parsed = resolveRequestSchema.parse(req.body)
      const result = await resolveChallenge(parsed)
      res.json(ok(result))
    } catch (err) {
      const safe = sanitizeError('recovery/discovery/resolve', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
