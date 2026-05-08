// Passkey-as-identity — Postgres CRUD.
// Tables live in `store/migrations/001_initial.sql`:
//   - ika_identity_passkeys
//   - ika_identity_passkey_challenges

import type { PoolClient } from 'pg'
import { getPool } from '../../store/pool.js'

// ── Challenge store ──────────────────────────────────────────────

export type PasskeyChallengeType = 'registration' | 'authentication'

export interface PasskeyChallengeRecord {
  challenge: string
  type: PasskeyChallengeType
  userHandle: string | null
  targetWalletAddress: string | null
  metadata: Record<string, unknown> | null
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

interface ChallengeRow {
  challenge: string
  challenge_type: string
  user_handle: string | null
  target_wallet_address: string | null
  metadata: Record<string, unknown> | null
  created_at: Date | string
  expires_at: Date | string
  consumed_at: Date | string | null
}

function rowToChallenge(row: ChallengeRow): PasskeyChallengeRecord {
  const toIso = (v: Date | string | null) =>
    v === null ? null : typeof v === 'string' ? v : v.toISOString()
  return {
    challenge: row.challenge,
    type: row.challenge_type === 'registration' ? 'registration' : 'authentication',
    userHandle: row.user_handle,
    targetWalletAddress: row.target_wallet_address,
    metadata: row.metadata,
    createdAt: toIso(row.created_at) as string,
    expiresAt: toIso(row.expires_at) as string,
    consumedAt: toIso(row.consumed_at),
  }
}

export interface CreatePasskeyChallengeInput {
  challenge: string
  type: PasskeyChallengeType
  ttlMs: number
  userHandle?: string | null
  targetWalletAddress?: string | null
  metadata?: Record<string, unknown> | null
}

export async function createPasskeyChallenge(
  input: CreatePasskeyChallengeInput,
): Promise<PasskeyChallengeRecord> {
  const pool = getPool()
  const expiresAt = new Date(Date.now() + input.ttlMs)
  const result = await pool.query<ChallengeRow>({
    name: 'passkey_challenge_create',
    text: `INSERT INTO ika_identity_passkey_challenges
             (challenge, challenge_type, user_handle, target_wallet_address, metadata, expires_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6)
             RETURNING challenge, challenge_type, user_handle, target_wallet_address, metadata, created_at, expires_at, consumed_at`,
    values: [
      input.challenge,
      input.type,
      input.userHandle ?? null,
      input.targetWalletAddress ?? null,
      input.metadata ? JSON.stringify(input.metadata) : null,
      expiresAt.toISOString(),
    ],
  })
  return rowToChallenge(result.rows[0]!)
}

export async function consumePasskeyChallenge(
  challenge: string,
  expectedType: PasskeyChallengeType,
): Promise<PasskeyChallengeRecord | null> {
  const pool = getPool()
  const result = await pool.query<ChallengeRow>({
    name: 'passkey_challenge_consume',
    text: `UPDATE ika_identity_passkey_challenges
              SET consumed_at = NOW()
              WHERE challenge = $1
                AND challenge_type = $2
                AND consumed_at IS NULL
                AND expires_at > NOW()
              RETURNING challenge, challenge_type, user_handle, target_wallet_address, metadata, created_at, expires_at, consumed_at`,
    values: [challenge, expectedType],
  })
  if (result.rows.length === 0) return null
  return rowToChallenge(result.rows[0]!)
}

// ── Identity passkey CRUD ────────────────────────────────────────

export interface IdentityPasskeyRecord {
  credentialId: string
  walletAddress: string
  publicKeyBase64: string
  counter: number
  transports: string[] | null
  deviceLabel: string | null
  createdAt: string
  lastUsedAt: string | null
}

interface PasskeyRow {
  credential_id: string
  wallet_address: string
  public_key_base64: string
  counter: string | number
  transports: unknown
  device_label: string | null
  created_at: Date | string
  last_used_at: Date | string | null
}

function rowToPasskey(row: PasskeyRow): IdentityPasskeyRecord {
  const toIso = (v: Date | string | null) =>
    v === null ? null : typeof v === 'string' ? v : v.toISOString()
  let transports: string[] | null = null
  if (Array.isArray(row.transports)) {
    transports = row.transports.filter((t): t is string => typeof t === 'string')
  }
  return {
    credentialId: row.credential_id,
    walletAddress: row.wallet_address,
    publicKeyBase64: row.public_key_base64,
    counter: typeof row.counter === 'string' ? Number.parseInt(row.counter, 10) : row.counter,
    transports,
    deviceLabel: row.device_label,
    createdAt: toIso(row.created_at) as string,
    lastUsedAt: toIso(row.last_used_at),
  }
}

export async function getIdentityPasskeyByCredentialId(
  credentialId: string,
): Promise<IdentityPasskeyRecord | null> {
  const pool = getPool()
  const result = await pool.query<PasskeyRow>({
    name: 'passkey_get_by_credential',
    text: `SELECT credential_id, wallet_address, public_key_base64, counter, transports, device_label, created_at, last_used_at
             FROM ika_identity_passkeys WHERE credential_id = $1 LIMIT 1`,
    values: [credentialId],
  })
  return result.rows[0] ? rowToPasskey(result.rows[0]) : null
}

export async function listIdentityPasskeysByWallet(
  walletAddress: string,
): Promise<IdentityPasskeyRecord[]> {
  const pool = getPool()
  const result = await pool.query<PasskeyRow>(
    `SELECT credential_id, wallet_address, public_key_base64, counter, transports, device_label, created_at, last_used_at
       FROM ika_identity_passkeys WHERE wallet_address = $1
       ORDER BY created_at DESC`,
    [walletAddress],
  )
  return result.rows.map(rowToPasskey)
}

export interface UpsertIdentityPasskeyInput {
  credentialId: string
  walletAddress: string
  publicKeyBase64: string
  counter: number
  transports?: string[] | null
  deviceLabel?: string | null
}

export async function upsertIdentityPasskey(
  input: UpsertIdentityPasskeyInput,
  client?: PoolClient,
): Promise<IdentityPasskeyRecord> {
  const executor = client ?? getPool()
  const result = await executor.query<PasskeyRow>(
    `INSERT INTO ika_identity_passkeys
       (credential_id, wallet_address, public_key_base64, counter, transports, device_label)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)
       ON CONFLICT (credential_id) DO UPDATE
         SET counter = GREATEST(ika_identity_passkeys.counter, EXCLUDED.counter),
             public_key_base64 = EXCLUDED.public_key_base64,
             transports = COALESCE(EXCLUDED.transports, ika_identity_passkeys.transports),
             device_label = COALESCE(EXCLUDED.device_label, ika_identity_passkeys.device_label),
             last_used_at = NOW()
         WHERE ika_identity_passkeys.wallet_address = EXCLUDED.wallet_address
       RETURNING credential_id, wallet_address, public_key_base64, counter, transports, device_label, created_at, last_used_at`,
    [
      input.credentialId,
      input.walletAddress,
      input.publicKeyBase64,
      input.counter,
      input.transports ? JSON.stringify(input.transports) : null,
      input.deviceLabel ?? null,
    ],
  )
  if (result.rows.length === 0) {
    throw new Error('Passkey credential is already registered for a different wallet')
  }
  return rowToPasskey(result.rows[0]!)
}

export async function advanceIdentityPasskeyCounter(
  credentialId: string,
  newCounter: number,
): Promise<{ accepted: boolean; record: IdentityPasskeyRecord | null }> {
  const pool = getPool()
  const result = await pool.query<PasskeyRow>(
    `UPDATE ika_identity_passkeys
       SET counter = GREATEST(counter, $2),
           last_used_at = NOW()
       WHERE credential_id = $1
         AND ($2 > counter OR counter = 0 OR $2 = 0)
       RETURNING credential_id, wallet_address, public_key_base64, counter, transports, device_label, created_at, last_used_at`,
    [credentialId, newCounter],
  )
  if (result.rows.length === 0) return { accepted: false, record: null }
  return { accepted: true, record: rowToPasskey(result.rows[0]!) }
}

export async function deleteIdentityPasskey(credentialId: string): Promise<boolean> {
  const pool = getPool()
  const result = await pool.query(
    `DELETE FROM ika_identity_passkeys WHERE credential_id = $1`,
    [credentialId],
  )
  return (result.rowCount ?? 0) > 0
}
