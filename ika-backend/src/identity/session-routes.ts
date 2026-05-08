import { Router } from 'express'
import { z } from 'zod'
import { fail, ok } from '../types.js'
import { sanitizeError } from '../safeError.js'
import { requireUserAuth } from './middleware.js'
import {
  exportIdentityForWallet,
  deleteIdentityForWallet,
  getIdentityByWalletAddress,
  listIdentityLinksByWallet,
  revokeAllRefreshTokensForWallet,
  revokeRefreshTokenByHash,
} from './store.js'
import {
  hashRefreshTokenValue,
  rotateRefreshToken,
  InvalidRefreshTokenError,
} from './jwt.js'
import { auditLog, hashIp } from './audit.js'
import type { IdentityProvider } from './types.js'

export function buildSessionRouter(): Router {
  const router = Router()

  router.get('/me', requireUserAuth, async (req, res) => {
    try {
      const wallet = req.userWalletAddress!
      // Parallel reads: identity + links são independentes.
      const [identity, links] = await Promise.all([
        getIdentityByWalletAddress(wallet),
        listIdentityLinksByWallet(wallet),
      ])
      if (!identity) {
        res.status(404).json(fail('Invalid identity'))
        return
      }
      res.json(
        ok({
          walletAddress: identity.walletAddress,
          primaryProvider: identity.primaryProvider,
          createdAt: identity.createdAt,
          updatedAt: identity.updatedAt,
          data: identity.data,
          links: links.map((l) => ({ provider: l.aliasProvider, subject: l.aliasSubject, createdAt: l.createdAt })),
        }),
      )
    } catch (err) {
      const safe = sanitizeError('identity/me', err)
      res.status(500).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/refresh', async (req, res) => {
    try {
      const schema = z.object({ refreshToken: z.string().min(1) })
      const { refreshToken } = schema.parse(req.body)
      const ipHash = hashIp(req.ip ?? null)
      const userAgent = req.headers['user-agent'] ?? null
      // Provider claim defaults to primary if rotation does not specify.
      const result = await rotateRefreshToken({
        refreshToken,
        provider: 'email' as IdentityProvider,
        primaryProvider: 'email' as IdentityProvider,
        userAgent: typeof userAgent === 'string' ? userAgent : null,
        ipHash,
      })
      void auditLog({
        walletAddress: result.walletAddress,
        eventType: 'identity.session.refreshed',
        ipHash,
        userAgent: typeof userAgent === 'string' ? userAgent : null,
      })
      res.json(
        ok({
          walletAddress: result.walletAddress,
          productJwt: result.productJwt,
          refreshToken: {
            token: result.refreshToken.token,
            expiresAt: result.refreshToken.expiresAt.toISOString(),
          },
        }),
      )
    } catch (err) {
      if (err instanceof InvalidRefreshTokenError) {
        res.status(401).json(fail(err.message))
        return
      }
      const safe = sanitizeError('identity/refresh', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.post('/logout', requireUserAuth, async (req, res) => {
    try {
      const wallet = req.userWalletAddress!
      const schema = z.object({ refreshToken: z.string().optional(), revokeAll: z.boolean().optional() })
      const { refreshToken, revokeAll } = schema.parse(req.body ?? {})
      let revoked = 0
      if (revokeAll) {
        revoked = await revokeAllRefreshTokensForWallet(wallet)
      } else if (refreshToken) {
        const tokenHash = hashRefreshTokenValue(refreshToken)
        await revokeRefreshTokenByHash(tokenHash)
        revoked = 1
      }
      void auditLog({
        walletAddress: wallet,
        eventType: 'identity.session.revoked',
        metadata: {},
      })
      res.json(ok({ revoked }))
    } catch (err) {
      const safe = sanitizeError('identity/logout', err)
      res.status(400).json(fail(safe.message, safe.traceId))
    }
  })

  router.get('/me/export', requireUserAuth, async (req, res) => {
    try {
      const wallet = req.userWalletAddress!
      const bundle = await exportIdentityForWallet(wallet)
      if (!bundle) {
        res.status(404).json(fail('Invalid identity'))
        return
      }
      void auditLog({
        walletAddress: wallet,
        eventType: 'identity.gdpr.exported',
      })
      res.json(ok(bundle))
    } catch (err) {
      const safe = sanitizeError('identity/me/export', err)
      res.status(500).json(fail(safe.message, safe.traceId))
    }
  })

  router.delete('/me', requireUserAuth, async (req, res) => {
    try {
      const wallet = req.userWalletAddress!
      const outcome = await deleteIdentityForWallet(wallet)
      void auditLog({
        walletAddress: wallet,
        eventType: 'identity.gdpr.deleted',
        metadata: {},
      })
      res.json(ok(outcome))
    } catch (err) {
      const safe = sanitizeError('identity/me/delete', err)
      res.status(500).json(fail(safe.message, safe.traceId))
    }
  })

  return router
}
