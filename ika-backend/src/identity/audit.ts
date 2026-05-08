// Identity layer — sanitized audit log.
// Allowlisted events + redacted metadata. Failures swallowed.

import { createHash } from 'node:crypto'
import { getPool } from '../store/pool.js'
import { logger } from '../logger.js'
import { getIdentityConfig } from './config.js'

const ALLOWED_EVENTS = new Set([
  // Session lifecycle
  'identity.session.created',
  'identity.session.refreshed',
  'identity.session.revoked',
  // Account linking
  'link.oauth',
  'link.email',
  'link.passkey',
  'unlink',
  // GDPR
  'identity.gdpr.exported',
  'identity.gdpr.deleted',
  // Email magic-link
  'email.request',
  'email.verify',
  // Email session
  'login.email',
  // Passkey
  'register.passkey',
  'login.passkey',
  // OAuth
  'login.oauth',
  // Recovery
  'recovery.policy.deployed',
  'recovery.policy.changed',
  'recovery.policy.revoked',
  'recovery.primary.used',
  'recovery.quorum.session.started',
  'recovery.quorum.session.finalized',
  'recovery.discovery.resolved',
])

const ALLOWED_KEYS = new Set([
  'isNew',
  'primaryProvider',
  'provider',
  'aliasProvider',
  'aliasSubject',
  'subject',
  'reason',
  'recoveryMode',
  'membersUsed',
  'amount',
  'cooldownSeconds',
  'previousVersion',
  'newVersion',
  'opKind',
  'alreadyLinked',
  'oauthProviderId',
  'credentialId',
  'displayName',
])

function clamp(value: unknown): unknown {
  if (typeof value === 'string') return value.slice(0, 256)
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'bigint') return value.toString()
  if (Array.isArray(value)) return value.slice(0, 32).map(clamp)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as object)) {
      if (!ALLOWED_KEYS.has(key)) continue
      out[key] = clamp((value as Record<string, unknown>)[key])
    }
    return out
  }
  return null
}

export function hashIp(ip: string | undefined | null): string | null {
  if (!ip) return null
  return createHash('sha256').update(ip, 'utf8').digest('hex').slice(0, 32)
}

export interface AuditLogInput {
  walletAddress?: string | null
  eventType: string
  provider?: string | null
  metadata?: Record<string, unknown>
  ipHash?: string | null
  userAgent?: string | null
}

export const recordAuditEvent = (input: AuditLogInput): Promise<void> => auditLog(input)

export async function auditLog(input: AuditLogInput): Promise<void> {
  if (!getIdentityConfig().persistence.auditLogEnabled) return
  if (!ALLOWED_EVENTS.has(input.eventType)) return
  try {
    const sanitized = input.metadata ? (clamp(input.metadata) as Record<string, unknown>) : null
    await getPool().query(
      `INSERT INTO ika_identity_audit(wallet_address, event_type, provider, metadata, ip_hash, user_agent)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6)`,
      [
        input.walletAddress ?? null,
        input.eventType,
        input.provider ?? null,
        sanitized ? JSON.stringify(sanitized) : null,
        input.ipHash ?? null,
        input.userAgent?.slice(0, 256) ?? null,
      ],
    )
  } catch (err) {
    logger.warn({ err, event: input.eventType }, 'audit log write failed (swallowed)')
  }
}
