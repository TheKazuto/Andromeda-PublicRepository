// OAuth — state + code_verifier persistence.

import type { PoolClient } from 'pg'
import { getPool } from '../../store/pool.js'

const STATE_TTL_MS = 10 * 60 * 1000

export type OauthStateIntent = 'login' | 'link'

export interface OauthStateRecord {
  state: string
  provider: string
  codeVerifier: string
  redirectUri: string
  intent: OauthStateIntent
  primaryWalletAddress: string | null
  createdAt: string
  expiresAt: string
}

export interface CreateOauthStateInput {
  state: string
  provider: string
  codeVerifier: string
  redirectUri: string
  intent?: OauthStateIntent
  primaryWalletAddress?: string | null
  ttlMs?: number
}

interface Row {
  state: string
  provider: string
  code_verifier: string
  redirect_uri: string
  intent: string
  primary_wallet_address: string | null
  created_at: Date | string
  expires_at: Date | string
}

function rowToRecord(row: Row): OauthStateRecord {
  const toIso = (v: Date | string) => (typeof v === 'string' ? v : v.toISOString())
  return {
    state: row.state,
    provider: row.provider,
    codeVerifier: row.code_verifier,
    redirectUri: row.redirect_uri,
    intent: (row.intent === 'link' ? 'link' : 'login') as OauthStateIntent,
    primaryWalletAddress: row.primary_wallet_address,
    createdAt: toIso(row.created_at),
    expiresAt: toIso(row.expires_at),
  }
}

export async function createOauthState(input: CreateOauthStateInput): Promise<OauthStateRecord> {
  const pool = getPool()
  const ttl = input.ttlMs ?? STATE_TTL_MS
  const expiresAt = new Date(Date.now() + ttl)
  const result = await pool.query<Row>({
    name: 'oauth_state_create',
    text: `INSERT INTO ika_identity_oauth_states
             (state, provider, code_verifier, redirect_uri, intent, primary_wallet_address, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING state, provider, code_verifier, redirect_uri, intent, primary_wallet_address, created_at, expires_at`,
    values: [
      input.state,
      input.provider,
      input.codeVerifier,
      input.redirectUri,
      input.intent ?? 'login',
      input.primaryWalletAddress ?? null,
      expiresAt.toISOString(),
    ],
  })
  return rowToRecord(result.rows[0]!)
}

export async function consumeOauthState(
  state: string,
  client?: PoolClient,
): Promise<OauthStateRecord | null> {
  const executor = client ?? getPool()
  // Named statements only on the pool — explicit clients in transactions
  // are kept unnamed.
  const result = client
    ? await executor.query<Row>(
        `DELETE FROM ika_identity_oauth_states
           WHERE state = $1
           RETURNING state, provider, code_verifier, redirect_uri, intent, primary_wallet_address, created_at, expires_at`,
        [state],
      )
    : await getPool().query<Row>({
        name: 'oauth_state_consume',
        text: `DELETE FROM ika_identity_oauth_states
                 WHERE state = $1
                 RETURNING state, provider, code_verifier, redirect_uri, intent, primary_wallet_address, created_at, expires_at`,
        values: [state],
      })
  if (result.rows.length === 0) return null
  return rowToRecord(result.rows[0]!)
}

export function isOauthStateExpired(record: OauthStateRecord, now = Date.now()): boolean {
  return new Date(record.expiresAt).getTime() <= now
}
