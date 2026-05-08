// Identity layer — Postgres persistence.
// Schema lives in store/migrations/001_initial.sql.
//
// PII columns (`data` JSONB on identities/links and `email` TEXT on
// email_tokens) are encrypted at rest via `./crypto/pii.ts` envelope
// encryption. Legacy plaintext rows continue to read transparently.

import { createHash } from 'node:crypto'
import type { PoolClient } from 'pg'
import { getPool } from '../store/pool.js'
import { unwrapDataFromStorage, wrapDataForStorage } from './crypto/pii.js'
import type {
  IdentityLinkRecord,
  IdentityProvider,
  IdentityRecord,
  IdentityRecordData,
  RefreshTokenRecord,
} from './types.js'

// ── Immutable config (PRF salt fingerprint) ──────────────────────

export const IDENTITY_CONFIG_KEYS = {
  passkeyPrfSalt: 'passkey_prf_salt',
} as const

function fingerprint(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

export async function assertConfigFingerprintImmutable(key: string, value: string): Promise<void> {
  const pool = getPool()
  const hash = fingerprint(value)
  const existing = await pool.query<{ value_hash: string }>({
    name: 'identity_config_select',
    text: 'SELECT value_hash FROM ika_identity_config WHERE config_key = $1 LIMIT 1',
    values: [key],
  })
  if (existing.rows.length === 0) {
    await pool.query({
      name: 'identity_config_insert',
      text: `INSERT INTO ika_identity_config (config_key, value_hash)
             VALUES ($1, $2)
             ON CONFLICT (config_key) DO NOTHING`,
      values: [key, hash],
    })
    return
  }
  if (existing.rows[0]!.value_hash !== hash) {
    throw new Error(
      `[ika-backend][identity] CRITICAL: ${key} changed since first boot. ` +
        'Rotating this value orphans every derived walletAddress. ' +
        'Restore the original value or wipe ika_identity_config (data loss).',
    )
  }
}

// ── Identity CRUD ────────────────────────────────────────────────

interface IdentityRow {
  wallet_address: string
  primary_provider: string
  primary_subject: string
  data: IdentityRecordData
  created_at: string | Date
  updated_at: string | Date
}

function rowToIdentity(row: IdentityRow): IdentityRecord {
  return {
    walletAddress: row.wallet_address,
    primaryProvider: row.primary_provider as IdentityProvider,
    primarySubject: row.primary_subject,
    data: (unwrapDataFromStorage(row.data) ?? {}) as IdentityRecordData,
    createdAt: typeof row.created_at === 'string' ? row.created_at : row.created_at.toISOString(),
    updatedAt: typeof row.updated_at === 'string' ? row.updated_at : row.updated_at.toISOString(),
  }
}

export interface UpsertIdentityInput {
  walletAddress: string
  primaryProvider: IdentityProvider
  primarySubject: string
  data?: IdentityRecordData
}

export interface UpsertIdentityResult {
  identity: IdentityRecord
  isNew: boolean
}

function isEmptyData(data: IdentityRecordData | undefined): boolean {
  if (!data) return true
  for (const _ in data) return false
  return true
}

interface UpsertReturningRow extends IdentityRow {
  is_new: boolean
}

export async function upsertIdentity(input: UpsertIdentityInput): Promise<UpsertIdentityResult> {
  const pool = getPool()
  const newData = input.data ?? {}

  // Fast path: when no PII payload is provided (most logins with default
  // persistEmail/persistDisplayName=false), there is nothing to merge.
  // A single statement avoids the SELECT FOR UPDATE roundtrip + lock.
  // `xmax = 0` distinguishes a fresh insert from an updated row.
  if (isEmptyData(newData)) {
    const result = await pool.query<UpsertReturningRow>({
      name: 'identity_upsert_fast',
      text: `INSERT INTO ika_identities (wallet_address, primary_provider, primary_subject, data)
             VALUES ($1, $2, $3, '{}'::jsonb)
             ON CONFLICT (wallet_address) DO UPDATE
               SET updated_at = NOW()
             RETURNING wallet_address, primary_provider, primary_subject, data, created_at, updated_at,
                       (xmax = 0) AS is_new`,
      values: [input.walletAddress, input.primaryProvider, input.primarySubject],
    })
    const row = result.rows[0]!
    return { identity: rowToIdentity(row), isNew: row.is_new }
  }

  // Slow path: encrypted envelopes can't be merged server-side, so we
  // read-modify-write inside a transaction to preserve atomicity.
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const existing = await client.query<IdentityRow>(
      `SELECT wallet_address, primary_provider, primary_subject, data, created_at, updated_at
         FROM ika_identities WHERE wallet_address = $1 FOR UPDATE`,
      [input.walletAddress],
    )
    const isNew = existing.rows.length === 0
    let mergedData: IdentityRecordData
    if (isNew) {
      mergedData = newData
    } else {
      const prevDecrypted = (unwrapDataFromStorage(existing.rows[0]!.data) ?? {}) as IdentityRecordData
      mergedData = { ...prevDecrypted, ...newData }
    }
    const wrapped = wrapDataForStorage(mergedData)
    const result = await client.query<IdentityRow>(
      `INSERT INTO ika_identities (wallet_address, primary_provider, primary_subject, data)
         VALUES ($1, $2, $3, $4::jsonb)
         ON CONFLICT (wallet_address) DO UPDATE
           SET data = EXCLUDED.data, updated_at = NOW()
         RETURNING wallet_address, primary_provider, primary_subject, data, created_at, updated_at`,
      [
        input.walletAddress,
        input.primaryProvider,
        input.primarySubject,
        JSON.stringify(wrapped),
      ],
    )
    await client.query('COMMIT')
    return { identity: rowToIdentity(result.rows[0]!), isNew }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
}

export async function getIdentityByWalletAddress(walletAddress: string): Promise<IdentityRecord | null> {
  const pool = getPool()
  const result = await pool.query<IdentityRow>({
    name: 'identity_get_by_wallet',
    text: `SELECT wallet_address, primary_provider, primary_subject, data, created_at, updated_at
             FROM ika_identities WHERE wallet_address = $1 LIMIT 1`,
    values: [walletAddress],
  })
  return result.rows[0] ? rowToIdentity(result.rows[0]) : null
}

export async function getIdentityByProviderSubject(
  provider: IdentityProvider,
  subject: string,
): Promise<IdentityRecord | null> {
  const pool = getPool()
  const result = await pool.query<IdentityRow>({
    name: 'identity_get_by_provider_subject',
    text: `SELECT wallet_address, primary_provider, primary_subject, data, created_at, updated_at
             FROM ika_identities WHERE primary_provider = $1 AND primary_subject = $2 LIMIT 1`,
    values: [provider, subject],
  })
  return result.rows[0] ? rowToIdentity(result.rows[0]) : null
}

/**
 * Single-roundtrip resolver used by the session pipeline. Tries:
 *   1. alias link → primary identity (if linked)
 *   2. identity by (provider, subject)
 *
 * Returns the resolved (walletAddress, primaryProvider) when found, else null.
 */
export async function resolveIdentityForLogin(
  provider: IdentityProvider,
  subject: string,
): Promise<{ walletAddress: string; primaryProvider: IdentityProvider } | null> {
  const pool = getPool()
  const result = await pool.query<{ wallet_address: string; primary_provider: string }>({
    name: 'identity_resolve_for_login',
    text: `
      WITH alias AS (
        SELECT i.wallet_address, i.primary_provider
          FROM ika_identity_links l
          JOIN ika_identities i ON i.wallet_address = l.primary_wallet_address
         WHERE l.alias_provider = $1 AND l.alias_subject = $2
         LIMIT 1
      ),
      direct AS (
        SELECT wallet_address, primary_provider
          FROM ika_identities
         WHERE primary_provider = $1 AND primary_subject = $2
         LIMIT 1
      )
      SELECT * FROM alias
      UNION ALL
      SELECT * FROM direct WHERE NOT EXISTS (SELECT 1 FROM alias)
      LIMIT 1
    `,
    values: [provider, subject],
  })
  const row = result.rows[0]
  if (!row) return null
  return {
    walletAddress: row.wallet_address,
    primaryProvider: row.primary_provider as IdentityProvider,
  }
}

// ── Links CRUD ───────────────────────────────────────────────────

interface LinkRow {
  alias_provider: string
  alias_subject: string
  primary_wallet_address: string
  data: IdentityRecordData
  created_at: Date | string
}

function rowToLink(row: LinkRow): IdentityLinkRecord {
  const toIso = (v: Date | string) => (typeof v === 'string' ? v : v.toISOString())
  return {
    aliasProvider: row.alias_provider as IdentityProvider,
    aliasSubject: row.alias_subject,
    primaryWalletAddress: row.primary_wallet_address,
    data: (unwrapDataFromStorage(row.data) ?? {}) as IdentityRecordData,
    createdAt: toIso(row.created_at),
  }
}

export async function getIdentityLink(
  provider: IdentityProvider,
  subject: string,
): Promise<IdentityLinkRecord | null> {
  const pool = getPool()
  const result = await pool.query<LinkRow>({
    name: 'identity_link_get',
    text: `SELECT alias_provider, alias_subject, primary_wallet_address, data, created_at
             FROM ika_identity_links
             WHERE alias_provider = $1 AND alias_subject = $2 LIMIT 1`,
    values: [provider, subject],
  })
  return result.rows[0] ? rowToLink(result.rows[0]) : null
}

export async function listIdentityLinksByWallet(walletAddress: string): Promise<IdentityLinkRecord[]> {
  const pool = getPool()
  const result = await pool.query<LinkRow>({
    name: 'identity_links_by_wallet',
    text: `SELECT alias_provider, alias_subject, primary_wallet_address, data, created_at
             FROM ika_identity_links
             WHERE primary_wallet_address = $1
             ORDER BY created_at ASC`,
    values: [walletAddress],
  })
  return result.rows.map(rowToLink)
}

export interface CreateIdentityLinkInput {
  aliasProvider: IdentityProvider
  aliasSubject: string
  primaryWalletAddress: string
  data?: IdentityRecordData
}

export interface CreateIdentityLinkResult {
  link: IdentityLinkRecord
  isNew: boolean
}

interface LinkUpsertRow extends LinkRow {
  is_new: boolean
}

export async function createIdentityLink(
  input: CreateIdentityLinkInput,
): Promise<CreateIdentityLinkResult> {
  const pool = getPool()
  const newData = input.data ?? {}

  // Fast path: empty payload → single statement, no read-modify-write.
  if (isEmptyData(newData)) {
    // Detect "alias already linked to a different wallet" without a
    // separate SELECT: we use a guarded UPSERT that only updates when
    // the existing row already belongs to the caller. If the row exists
    // and belongs to someone else, the UPDATE matches zero rows and we
    // fall through to a quick lookup to surface the conflict.
    const result = await pool.query<LinkUpsertRow>({
      name: 'identity_link_upsert_fast',
      text: `INSERT INTO ika_identity_links
               (alias_provider, alias_subject, primary_wallet_address, data)
             VALUES ($1, $2, $3, '{}'::jsonb)
             ON CONFLICT (alias_provider, alias_subject) DO UPDATE
               SET data = ika_identity_links.data
               WHERE ika_identity_links.primary_wallet_address = EXCLUDED.primary_wallet_address
             RETURNING alias_provider, alias_subject, primary_wallet_address, data, created_at,
                       (xmax = 0) AS is_new`,
      values: [input.aliasProvider, input.aliasSubject, input.primaryWalletAddress],
    })
    if (result.rows.length === 0) {
      throw new Error('Alias is already linked to a different wallet')
    }
    const row = result.rows[0]!
    return { link: rowToLink(row), isNew: row.is_new }
  }

  // Slow path: needs encrypted-envelope merge inside a transaction.
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const existing = await client.query<LinkRow>(
      `SELECT alias_provider, alias_subject, primary_wallet_address, data, created_at
         FROM ika_identity_links
         WHERE alias_provider = $1 AND alias_subject = $2 FOR UPDATE`,
      [input.aliasProvider, input.aliasSubject],
    )
    const isNew = existing.rows.length === 0
    if (!isNew && existing.rows[0]!.primary_wallet_address !== input.primaryWalletAddress) {
      await client.query('ROLLBACK')
      throw new Error('Alias is already linked to a different wallet')
    }
    let mergedData: IdentityRecordData
    if (isNew) {
      mergedData = newData
    } else {
      const prev = (unwrapDataFromStorage(existing.rows[0]!.data) ?? {}) as IdentityRecordData
      mergedData = { ...prev, ...newData }
    }
    const wrapped = wrapDataForStorage(mergedData)
    const result = await client.query<LinkRow>(
      `INSERT INTO ika_identity_links
         (alias_provider, alias_subject, primary_wallet_address, data)
         VALUES ($1, $2, $3, $4::jsonb)
         ON CONFLICT (alias_provider, alias_subject) DO UPDATE
           SET data = EXCLUDED.data
         RETURNING alias_provider, alias_subject, primary_wallet_address, data, created_at`,
      [
        input.aliasProvider,
        input.aliasSubject,
        input.primaryWalletAddress,
        JSON.stringify(wrapped),
      ],
    )
    await client.query('COMMIT')
    return { link: rowToLink(result.rows[0]!), isNew }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
}

export async function deleteIdentityLink(
  provider: IdentityProvider,
  subject: string,
): Promise<boolean> {
  const pool = getPool()
  const result = await pool.query({
    name: 'identity_link_delete',
    text: `DELETE FROM ika_identity_links WHERE alias_provider = $1 AND alias_subject = $2`,
    values: [provider, subject],
  })
  return (result.rowCount ?? 0) > 0
}

// ── Refresh tokens ───────────────────────────────────────────────

export function hashRefreshTokenValue(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

interface RefreshTokenRow {
  token_hash: string
  wallet_address: string
  created_at: string | Date
  expires_at: string | Date
  revoked_at: string | Date | null
  user_agent: string | null
  ip_hash: string | null
}

function rowToRefreshToken(row: RefreshTokenRow): RefreshTokenRecord {
  const toIso = (v: string | Date | null) =>
    v === null ? null : typeof v === 'string' ? v : v.toISOString()
  return {
    tokenHash: row.token_hash,
    walletAddress: row.wallet_address,
    createdAt: toIso(row.created_at) as string,
    expiresAt: toIso(row.expires_at) as string,
    revokedAt: toIso(row.revoked_at),
    userAgent: row.user_agent,
    ipHash: row.ip_hash,
  }
}

export interface CreateRefreshTokenInput {
  tokenHash: string
  walletAddress: string
  expiresAt: Date
  userAgent?: string | null
  ipHash?: string | null
}

export async function createRefreshToken(
  input: CreateRefreshTokenInput,
  client?: PoolClient,
): Promise<void> {
  const executor = client ?? getPool()
  // Note: prepared statements cannot be used on an explicit PoolClient that
  // is mid-transaction in pg, so we keep the unnamed form when `client` is
  // provided and named otherwise.
  if (client) {
    await executor.query(
      `INSERT INTO ika_identity_refresh_tokens
         (token_hash, wallet_address, expires_at, user_agent, ip_hash)
         VALUES ($1, $2, $3, $4, $5)`,
      [
        input.tokenHash,
        input.walletAddress,
        input.expiresAt.toISOString(),
        input.userAgent ?? null,
        input.ipHash ?? null,
      ],
    )
    return
  }
  await getPool().query({
    name: 'refresh_token_create',
    text: `INSERT INTO ika_identity_refresh_tokens
             (token_hash, wallet_address, expires_at, user_agent, ip_hash)
             VALUES ($1, $2, $3, $4, $5)`,
    values: [
      input.tokenHash,
      input.walletAddress,
      input.expiresAt.toISOString(),
      input.userAgent ?? null,
      input.ipHash ?? null,
    ],
  })
}

export async function getRefreshTokenByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
  const pool = getPool()
  const result = await pool.query<RefreshTokenRow>({
    name: 'refresh_token_get',
    text: `SELECT token_hash, wallet_address, created_at, expires_at, revoked_at, user_agent, ip_hash
             FROM ika_identity_refresh_tokens
             WHERE token_hash = $1 LIMIT 1`,
    values: [tokenHash],
  })
  return result.rows[0] ? rowToRefreshToken(result.rows[0]) : null
}

export async function revokeRefreshTokenByHash(tokenHash: string, client?: PoolClient): Promise<void> {
  const executor = client ?? getPool()
  if (client) {
    await executor.query(
      `UPDATE ika_identity_refresh_tokens
         SET revoked_at = NOW()
         WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash],
    )
    return
  }
  await getPool().query({
    name: 'refresh_token_revoke',
    text: `UPDATE ika_identity_refresh_tokens
             SET revoked_at = NOW()
             WHERE token_hash = $1 AND revoked_at IS NULL`,
    values: [tokenHash],
  })
}

/**
 * Atomic rotate-by-hash used by the refresh flow. Verifies the row is
 * usable (not revoked, not expired) and revokes it in one statement,
 * returning the wallet so the caller can issue a new pair without a
 * separate SELECT roundtrip.
 */
export async function consumeRefreshTokenForRotation(
  tokenHash: string,
  client?: PoolClient,
): Promise<{ walletAddress: string } | null> {
  const executor = client ?? getPool()
  const result = await executor.query<{ wallet_address: string }>(
    `UPDATE ika_identity_refresh_tokens
        SET revoked_at = NOW()
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND expires_at > NOW()
        RETURNING wallet_address`,
    [tokenHash],
  )
  if (result.rows.length === 0) return null
  return { walletAddress: result.rows[0]!.wallet_address }
}

export async function revokeAllRefreshTokensForWallet(walletAddress: string): Promise<number> {
  const pool = getPool()
  const result = await pool.query({
    name: 'refresh_tokens_revoke_all',
    text: `UPDATE ika_identity_refresh_tokens
             SET revoked_at = NOW()
             WHERE wallet_address = $1 AND revoked_at IS NULL`,
    values: [walletAddress],
  })
  return result.rowCount ?? 0
}

export async function withIdentityTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const pool = getPool()
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
}

// ── GDPR ─────────────────────────────────────────────────────────

export interface IdentityExportBundle {
  walletAddress: string
  identity: IdentityRecord
  links: IdentityLinkRecord[]
  refreshTokenCount: number
  exportedAt: string
}

export async function exportIdentityForWallet(walletAddress: string): Promise<IdentityExportBundle | null> {
  const pool = getPool()
  // 3 reads independentes — paralelizar elimina 2 RTTs.
  const [identity, links, refreshTokenResult] = await Promise.all([
    getIdentityByWalletAddress(walletAddress),
    listIdentityLinksByWallet(walletAddress),
    pool.query<{ count: string }>({
      name: 'refresh_tokens_count_active',
      text: `SELECT COUNT(*)::TEXT AS count
               FROM ika_identity_refresh_tokens
               WHERE wallet_address = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
      values: [walletAddress],
    }),
  ])
  if (!identity) return null
  const refreshTokenCount = Number.parseInt(refreshTokenResult.rows[0]?.count ?? '0', 10)
  return {
    walletAddress,
    identity,
    links,
    refreshTokenCount,
    exportedAt: new Date().toISOString(),
  }
}

export interface IdentityDeleteOutcome {
  walletAddress: string
  alreadyDeleted: boolean
  removed: {
    identity: boolean
    links: number
    refreshTokens: number
    auditLog: number
  }
  deletedAt: string
}

/**
 * GDPR delete. ON DELETE CASCADE on links/passkeys/refresh_tokens means a
 * single DELETE on ika_identities removes everything except the audit log
 * (which intentionally has no FK so events survive the user). A CTE captures
 * counts in one round-trip.
 */
export async function deleteIdentityForWallet(walletAddress: string): Promise<IdentityDeleteOutcome> {
  const pool = getPool()
  const result = await pool.query<{
    identity_removed: number
    links_removed: number
    refresh_removed: number
    audit_removed: number
  }>(
    `WITH
       links_count AS (
         SELECT COUNT(*)::INT AS n FROM ika_identity_links WHERE primary_wallet_address = $1
       ),
       refresh_count AS (
         SELECT COUNT(*)::INT AS n FROM ika_identity_refresh_tokens WHERE wallet_address = $1
       ),
       deleted_identity AS (
         DELETE FROM ika_identities WHERE wallet_address = $1 RETURNING 1
       ),
       deleted_audit AS (
         DELETE FROM ika_identity_audit WHERE wallet_address = $1 RETURNING 1
       )
       SELECT
         COALESCE((SELECT COUNT(*)::INT FROM deleted_identity), 0) AS identity_removed,
         (SELECT n FROM links_count)                              AS links_removed,
         (SELECT n FROM refresh_count)                            AS refresh_removed,
         COALESCE((SELECT COUNT(*)::INT FROM deleted_audit), 0)   AS audit_removed`,
    [walletAddress],
  )
  const row = result.rows[0]!
  const identityRemoved = row.identity_removed > 0
  return {
    walletAddress,
    alreadyDeleted: !identityRemoved && row.links_removed === 0,
    removed: {
      identity: identityRemoved,
      links: row.links_removed,
      refreshTokens: row.refresh_removed,
      auditLog: row.audit_removed,
    },
    deletedAt: new Date().toISOString(),
  }
}
