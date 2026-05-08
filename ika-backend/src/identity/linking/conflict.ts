// Account linking — collision detection.

import { getIdentityByProviderSubject, getIdentityLink } from '../store.js'
import type { IdentityProvider } from '../types.js'

export type LinkAvailability =
  | { state: 'available' }
  | { state: 'already-linked-to-self' }
  | { state: 'conflict-primary'; otherWalletAddress: string }
  | { state: 'conflict-alias'; otherWalletAddress: string }

export async function evaluateLinkAvailability(
  provider: IdentityProvider,
  subject: string,
  primaryWalletAddress: string,
): Promise<LinkAvailability> {
  const primary = await getIdentityByProviderSubject(provider, subject)
  if (primary) {
    if (primary.walletAddress === primaryWalletAddress) {
      return { state: 'already-linked-to-self' }
    }
    return { state: 'conflict-primary', otherWalletAddress: primary.walletAddress }
  }

  const link = await getIdentityLink(provider, subject)
  if (link) {
    if (link.primaryWalletAddress === primaryWalletAddress) {
      return { state: 'already-linked-to-self' }
    }
    return { state: 'conflict-alias', otherWalletAddress: link.primaryWalletAddress }
  }

  return { state: 'available' }
}

export class LinkConflictError extends Error {
  readonly statusCode = 409
  constructor(
    message: string,
    readonly reason: 'conflict-primary' | 'conflict-alias',
  ) {
    super(message)
    this.name = 'LinkConflictError'
  }
}
