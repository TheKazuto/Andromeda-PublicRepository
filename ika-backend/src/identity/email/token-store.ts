// Email — token store CRUD.
// Each /email/request inserts a row in `ika_identity_email_tokens` keyed
// by sha256(token). /verify consumes the row in a single atomic UPDATE.
//
// The `email` column stores PII and is encrypted at rest via the envelope
// from `../crypto/pii.ts`. Legacy plaintext rows continue to read via the
// transparent fallback in `decryptTextColumn`.

import { createHash, randomBytes } from 'node:crypto'
import { getPool } from '../../store/pool.js'
import { decryptTextColumn, encryptTextColumn } from '../crypto/pii.js'

export type EmailTokenIntent = 'login' | 'link'

export interface EmailTokenRecord {
  tokenHash: string
  email: string
  intent: EmailTokenIntent
  primaryWalletAddress: string | null
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

interface Row {
  token_hash: string
  email: string
  intent: string
  primary_wallet_address: string | null
  created_at: Date | string
  expires_at: Date | string
  consumed_at: Date | string | null
}

function rowToRecord(row: Row): EmailTokenRecord {
  const toIso = (v: Date | string | null) =>
    v === null ? null : typeof v === 'string' ? v : v.toISOString()
  return {
    tokenHash: row.token_hash,
    email: decryptTextColumn(row.email) ?? '',
    intent: (row.intent === 'link' ? 'link' : 'login') as EmailTokenIntent,
    primaryWalletAddress: row.primary_wallet_address,
    createdAt: toIso(row.created_at) as string,
    expiresAt: toIso(row.expires_at) as string,
    consumedAt: toIso(row.consumed_at),
  }
}

export function hashEmailToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

export interface GeneratedEmailToken {
  token: string
  tokenHash: string
}

export function generateEmailToken(): GeneratedEmailToken {
  const token = randomBytes(32).toString('base64url')
  return { token, tokenHash: hashEmailToken(token) }
}

export interface CreateEmailTokenInput {
  tokenHash: string
  email: string
  intent: EmailTokenIntent
  primaryWalletAddress?: string | null
  ttlSeconds: number
}

export async function createEmailToken(input: CreateEmailTokenInput): Promise<EmailTokenRecord> {
  const pool = getPool()
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000)
  const result = await pool.query<Row>({
    name: 'email_token_create',
    text: `INSERT INTO ika_identity_email_tokens
             (token_hash, email, intent, primary_wallet_address, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING token_hash, email, intent, primary_wallet_address, created_at, expires_at, consumed_at`,
    values: [
      input.tokenHash,
      encryptTextColumn(input.email),
      input.intent,
      input.primaryWalletAddress ?? null,
      expiresAt.toISOString(),
    ],
  })
  return rowToRecord(result.rows[0]!)
}

export async function consumeEmailToken(tokenHash: string): Promise<EmailTokenRecord | null> {
  const pool = getPool()
  const result = await pool.query<Row>({
    name: 'email_token_consume',
    text: `UPDATE ika_identity_email_tokens
              SET consumed_at = NOW()
              WHERE token_hash = $1
                AND consumed_at IS NULL
                AND expires_at > NOW()
              RETURNING token_hash, email, intent, primary_wallet_address, created_at, expires_at, consumed_at`,
    values: [tokenHash],
  })
  if (result.rows.length === 0) return null
  return rowToRecord(result.rows[0]!)
}
