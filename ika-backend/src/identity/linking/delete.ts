// Account linking — DELETE /:provider/:subject (remove an alias).

import type { Request, Response } from 'express'
import { fail, ok } from '../../types.js'
import { sanitizeError } from '../../safeError.js'
import { recordAuditEvent } from '../audit.js'
import { deleteIdentityLink, getIdentityLink, listIdentityLinksByWallet } from '../store.js'
import { buildIpHash, readUserAgent, requireAuthedWallet } from './common.js'
import type { IdentityProvider } from '../types.js'

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
