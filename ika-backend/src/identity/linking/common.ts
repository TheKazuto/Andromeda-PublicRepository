// Account linking — shared helpers for the per-provider link handlers.
//
// Each linking endpoint requires a Bearer JWT (the wallet being linked TO must
// already be authenticated). After provider-specific verification, an alias row
// is added to ika_identity_links pointing back to the user's wallet.

import { createHash } from 'node:crypto'
import type { Request, Response } from 'express'
import { fail } from '../../types.js'
import { evaluateLinkAvailability, LinkConflictError } from './conflict.js'
import { createIdentityLink } from '../store.js'
import type { IdentityProvider, IdentityRecordData } from '../types.js'

export function buildIpHash(req: Request): string | null {
  const ip = req.ip || req.socket?.remoteAddress
  if (!ip) return null
  return createHash('sha256').update(ip).digest('hex').slice(0, 32)
}

export function readUserAgent(req: Request): string | null {
  const ua = req.headers['user-agent']
  if (typeof ua !== 'string' || ua.length === 0) return null
  return ua.length > 512 ? ua.slice(0, 512) : ua
}

export function requireAuthedWallet(req: Request, res: Response): string | null {
  const wallet = req.userWalletAddress
  if (!wallet) {
    res.status(401).json(fail('Unauthorized'))
    return null
  }
  return wallet
}

export function buildLinkResponse(args: {
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

/**
 * Add (or recognise) the alias `provider:subject → primaryWalletAddress`.
 * Throws {@link LinkConflictError} if the identity is already owned elsewhere.
 */
export async function persistLinkOrConflict(args: {
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
