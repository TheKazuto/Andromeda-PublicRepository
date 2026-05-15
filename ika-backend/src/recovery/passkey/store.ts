/**
 * Postgres helpers for the passkey-PRF flow (Keyspring Fase 3 Bloco 3).
 *
 * Tables: see `src/store/migrations/015_passkey_credentials.sql`.
 * D4: ika-backend is the sole writer. The gateway never reads these tables;
 * it reverse-proxies and trusts the on-chain `RulesPolicy` for authority.
 */

import { randomBytes, randomUUID } from 'node:crypto'
import type { PoolClient } from 'pg'
import { getPool, query, withTransaction } from '../../store/pool.js'

// ── types ──────────────────────────────────────────────────────

export interface PasskeyCredentialRow {
  id: string
  tenant_id: string
  dwallet_address: string
  credential_id_hash: Buffer
  credential_public_key: Buffer
  enc_pub_key: Buffer | null
  rp_id: string
  origin: string
  salt_id: Buffer
  salt_hash: Buffer
  sign_count: string
  backup_eligible: boolean
  backup_state: boolean
  transports: string | null
  created_at: Date
  last_used_at: Date | null
  revoked_at: Date | null
}

export interface PasskeyCredentialView {
  id: string
  dwalletAddress: string
  credentialIdHash: Uint8Array
  credentialPublicKey: Uint8Array
  rpId: string
  origin: string
  saltId: Uint8Array
  saltHash: Uint8Array
  signCount: bigint
  backupEligible: boolean
  backupState: boolean
  transports: string[] | null
  createdAt: Date
  lastUsedAt: Date | null
  revokedAt: Date | null
}

function rowToView(r: PasskeyCredentialRow): PasskeyCredentialView {
  return {
    id: r.id,
    dwalletAddress: r.dwallet_address,
    credentialIdHash: Uint8Array.from(r.credential_id_hash),
    credentialPublicKey: Uint8Array.from(r.credential_public_key),
    rpId: r.rp_id,
    origin: r.origin,
    saltId: Uint8Array.from(r.salt_id),
    saltHash: Uint8Array.from(r.salt_hash),
    signCount: BigInt(r.sign_count),
    backupEligible: r.backup_eligible,
    backupState: r.backup_state,
    transports: r.transports ? r.transports.split(',').map((s) => s.trim()).filter(Boolean) : null,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    revokedAt: r.revoked_at,
  }
}

// ── passkey_credentials ─────────────────────────────────────────

/** D6: max 5 active credentials per dWallet. */
export const MAX_CREDENTIALS_PER_DWALLET = 5

export interface RegisterPasskeyCredentialInput {
  tenantId: string
  dwalletAddress: string
  credentialIdHash: Uint8Array
  credentialPublicKey: Uint8Array
  encPubKey?: Uint8Array | undefined
  rpId: string
  origin: string
  saltId: Uint8Array
  saltHash: Uint8Array
  signCount?: bigint | undefined
  backupEligible?: boolean | undefined
  backupState?: boolean | undefined
  transports?: string[] | undefined
}

/**
 * Persists a new passkey credential inside a single transaction that takes
 * an `ACCESS EXCLUSIVE`-equivalent lock on the dWallet's existing credential
 * rows (via `SELECT … FOR UPDATE`) before counting them — closes the race
 * window two concurrent `register-complete` calls could otherwise exploit
 * to push past `MAX_CREDENTIALS_PER_DWALLET` (D6).
 *
 * Also inserts the matching `recovery_bindings` row (scheme=3, binding_ref =
 * credential_id_hash) so the D5 last-active-method guard knows about it.
 *
 * Throws:
 *   - `MaxCredentialsPerDwalletError`  if the dWallet already has 5 active.
 *   - `DuplicateCredentialError`       if the same credentialId already
 *                                      registered (unique index on
 *                                      `credential_id_hash`).
 */
export async function registerPasskeyCredential(
  input: RegisterPasskeyCredentialInput,
): Promise<PasskeyCredentialView> {
  return withTransaction(async (client) => {
    // Lock-the-set: any concurrent insert/update on this dWallet's active
    // rows blocks until we commit. NOWAIT would surface a clearer error but
    // PG default lock waits are fine for a low-volume admin path.
    const lockRes = await client.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM passkey_credentials
        WHERE dwallet_address = $1 AND revoked_at IS NULL
        FOR UPDATE`,
      [input.dwalletAddress],
    )
    const active = Number.parseInt(lockRes.rows[0]?.count ?? '0', 10)
    if (active >= MAX_CREDENTIALS_PER_DWALLET) {
      throw new MaxCredentialsPerDwalletError(input.dwalletAddress, MAX_CREDENTIALS_PER_DWALLET)
    }
    const id = randomUUID()
    try {
      const { rows } = await client.query<PasskeyCredentialRow>(
        `INSERT INTO passkey_credentials(
           id, tenant_id, dwallet_address, credential_id_hash, credential_public_key,
           enc_pub_key, rp_id, origin, salt_id, salt_hash, sign_count,
           backup_eligible, backup_state, transports
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.dwalletAddress,
          Buffer.from(input.credentialIdHash),
          Buffer.from(input.credentialPublicKey),
          input.encPubKey ? Buffer.from(input.encPubKey) : null,
          input.rpId,
          input.origin,
          Buffer.from(input.saltId),
          Buffer.from(input.saltHash),
          (input.signCount ?? 0n).toString(),
          input.backupEligible ?? false,
          input.backupState ?? false,
          input.transports && input.transports.length > 0 ? input.transports.join(',') : null,
        ],
      )
      const created = rows[0]
      if (!created) throw new Error('insert returned no row')

      // Register the matching recovery_binding so D5 can find it.
      await client.query(
        `INSERT INTO recovery_bindings(id, tenant_id, dwallet_address, scheme, binding_ref, status)
         VALUES ($1, $2, $3, $4, $5, 'active')
         ON CONFLICT (dwallet_address, scheme, binding_ref) DO UPDATE
           SET status = 'active', revoked_at = NULL`,
        [
          randomUUID(),
          input.tenantId,
          input.dwalletAddress,
          3, // SCHEME_WEBAUTHN
          Buffer.from(input.credentialIdHash),
        ],
      )

      return rowToView(created)
    } catch (err: unknown) {
      if (isUniqueViolation(err)) {
        throw new DuplicateCredentialError(input.credentialIdHash)
      }
      throw err
    }
  })
}

export async function findPasskeyCredentialById(
  tenantId: string,
  id: string,
): Promise<PasskeyCredentialView | null> {
  const { rows } = await query<PasskeyCredentialRow>(
    `SELECT * FROM passkey_credentials WHERE id = $1 AND tenant_id = $2`,
    [id, tenantId],
  )
  const r = rows[0]
  return r ? rowToView(r) : null
}

export async function findPasskeyCredentialByHash(
  tenantId: string,
  credentialIdHash: Uint8Array,
): Promise<PasskeyCredentialView | null> {
  const { rows } = await query<PasskeyCredentialRow>(
    `SELECT * FROM passkey_credentials WHERE credential_id_hash = $1 AND tenant_id = $2`,
    [Buffer.from(credentialIdHash), tenantId],
  )
  const r = rows[0]
  return r ? rowToView(r) : null
}

export async function listActivePasskeyCredentials(
  tenantId: string,
  dwalletAddress: string,
): Promise<PasskeyCredentialView[]> {
  const { rows } = await query<PasskeyCredentialRow>(
    `SELECT * FROM passkey_credentials
      WHERE tenant_id = $1 AND dwallet_address = $2 AND revoked_at IS NULL
      ORDER BY created_at ASC`,
    [tenantId, dwalletAddress],
  )
  return rows.map(rowToView)
}

/**
 * Updates `sign_count` and `last_used_at` after a successful use. The on-chain
 * rules-policy doesn't track sign_count itself (it's a WebAuthn anti-clone
 * hint, not an auth decision — D11), so this is best-effort bookkeeping.
 */
export async function bumpPasskeyCredentialSignCount(
  tenantId: string,
  credentialIdHash: Uint8Array,
  newSignCount: bigint,
): Promise<void> {
  await query(
    `UPDATE passkey_credentials
        SET sign_count = $1, last_used_at = NOW()
      WHERE tenant_id = $2 AND credential_id_hash = $3 AND revoked_at IS NULL`,
    [newSignCount.toString(), tenantId, Buffer.from(credentialIdHash)],
  )
}

// ── recovery_bindings ───────────────────────────────────────────

export interface RecoveryBindingRow {
  id: string
  tenant_id: string
  dwallet_address: string
  scheme: number
  binding_ref: Buffer
  status: 'active' | 'revoked'
  created_at: Date
  revoked_at: Date | null
}

/**
 * Counts every active recovery binding on the dWallet. Used by the D5 guard
 * at revoke time: revoking the last active binding would leave the dWallet
 * with no recovery method and is rejected with HTTP 409.
 */
export async function countActiveRecoveryBindings(
  tenantId: string,
  dwalletAddress: string,
  client?: PoolClient,
): Promise<number> {
  const runner = client ?? getPool()
  const { rows } = await runner.query<{ count: string }>(
    `SELECT count(*)::text AS count
       FROM recovery_bindings
      WHERE tenant_id = $1 AND dwallet_address = $2 AND status = 'active'`,
    [tenantId, dwalletAddress],
  )
  return Number.parseInt(rows[0]?.count ?? '0', 10)
}

export async function listActiveRecoveryBindings(
  tenantId: string,
  dwalletAddress: string,
): Promise<RecoveryBindingRow[]> {
  const { rows } = await query<RecoveryBindingRow>(
    `SELECT * FROM recovery_bindings
      WHERE tenant_id = $1 AND dwallet_address = $2 AND status = 'active'
      ORDER BY created_at ASC`,
    [tenantId, dwalletAddress],
  )
  return rows
}

// ── revoke (D5 guard) ──────────────────────────────────────────

/**
 * Revokes a passkey credential AND its matching `recovery_bindings` row in a
 * single transaction. Enforces the D5 invariant — if revoking would leave the
 * dWallet without any active recovery method, throws
 * `LastActiveCredentialError` and the caller surfaces HTTP 409
 * `last_active_credential`.
 *
 * Returns `null` if no such credential (or already revoked).
 */
export async function revokePasskeyCredential(input: {
  tenantId: string
  credentialId: string
}): Promise<PasskeyCredentialView | null> {
  return withTransaction(async (client) => {
    // 1. Lock the credential row first.
    const credRes = await client.query<PasskeyCredentialRow>(
      `SELECT * FROM passkey_credentials
        WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        FOR UPDATE`,
      [input.credentialId, input.tenantId],
    )
    const cred = credRes.rows[0]
    if (!cred) return null

    // 2. Lock the bindings of this dWallet too — count is taken AFTER both
    //    locks are held to avoid the (rare) race against a concurrent
    //    register or other revoke on the same dWallet.
    await client.query(
      `SELECT 1 FROM recovery_bindings
        WHERE tenant_id = $1 AND dwallet_address = $2 AND status = 'active'
        FOR UPDATE`,
      [input.tenantId, cred.dwallet_address],
    )

    // 3. D5 guard.
    const active = await countActiveRecoveryBindings(input.tenantId, cred.dwallet_address, client)
    if (active <= 1) {
      throw new LastActiveCredentialError(cred.dwallet_address)
    }

    // 4. Revoke the credential + its binding.
    const updatedCredRes = await client.query<PasskeyCredentialRow>(
      `UPDATE passkey_credentials
          SET revoked_at = NOW()
        WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        RETURNING *`,
      [input.credentialId, input.tenantId],
    )
    const updatedCred = updatedCredRes.rows[0]
    if (!updatedCred) return null

    await client.query(
      `UPDATE recovery_bindings
          SET status = 'revoked', revoked_at = NOW()
        WHERE tenant_id = $1
          AND dwallet_address = $2
          AND scheme = 3
          AND binding_ref = $3
          AND status = 'active'`,
      [input.tenantId, cred.dwallet_address, cred.credential_id_hash],
    )

    return rowToView(updatedCred)
  })
}

// ── passkey_challenges ─────────────────────────────────────────

export type PasskeyChallengePurpose = 'register' | 'session_open' | 'sign'

export interface InsertPasskeyChallengeInput {
  tenantId: string
  purpose: PasskeyChallengePurpose
  challenge: Uint8Array
  dwalletAddress?: string | null
  credentialIdHash?: Uint8Array | null
  apiKeyId?: string | null
  metadata?: Record<string, unknown> | undefined
  ttlSeconds: number
}

export interface PasskeyChallengeRow {
  id: string
  tenant_id: string
  purpose: PasskeyChallengePurpose
  challenge: Buffer
  dwallet_address: string | null
  credential_id_hash: Buffer | null
  api_key_id: string | null
  metadata: Record<string, unknown>
  expires_at: Date
  used_at: Date | null
  created_at: Date
}

export async function insertPasskeyChallenge(
  input: InsertPasskeyChallengeInput,
): Promise<PasskeyChallengeRow> {
  if (input.challenge.length !== 32) {
    throw new Error(`passkey challenge must be 32 bytes (got ${input.challenge.length})`)
  }
  const id = randomUUID()
  const { rows } = await query<PasskeyChallengeRow>(
    `INSERT INTO passkey_challenges(
       id, tenant_id, purpose, challenge, dwallet_address, credential_id_hash,
       api_key_id, metadata, expires_at
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb, NOW() + ($9::int * interval '1 second'))
     RETURNING *`,
    [
      id,
      input.tenantId,
      input.purpose,
      Buffer.from(input.challenge),
      input.dwalletAddress ?? null,
      input.credentialIdHash ? Buffer.from(input.credentialIdHash) : null,
      input.apiKeyId ?? null,
      JSON.stringify(input.metadata ?? {}),
      input.ttlSeconds,
    ],
  )
  const created = rows[0]
  if (!created) throw new Error('insert returned no row')
  return created
}

/**
 * Atomically consume a single-use challenge. Returns the row only if it was
 * unconsumed AND not expired at the moment of the UPDATE. Concurrent calls
 * cannot both succeed.
 */
export async function consumePasskeyChallenge(
  tenantId: string,
  id: string,
): Promise<PasskeyChallengeRow | null> {
  const { rows } = await query<PasskeyChallengeRow>(
    `UPDATE passkey_challenges
        SET used_at = NOW()
      WHERE id = $1 AND tenant_id = $2 AND used_at IS NULL AND expires_at > NOW()
      RETURNING *`,
    [id, tenantId],
  )
  return rows[0] ?? null
}

// ── helpers ────────────────────────────────────────────────────

/** Generates a fresh 32-byte challenge for `purpose='register'` (no on-chain
 *  binding needed; this is a server-issued nonce included by the browser in
 *  `navigator.credentials.create({ publicKey: { challenge, … } })`). */
export function newRegisterChallenge(): Uint8Array {
  return new Uint8Array(randomBytes(32))
}

function isUniqueViolation(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false
  const code = (err as { code?: string }).code
  return code === '23505'
}

// ── error types ────────────────────────────────────────────────

export class MaxCredentialsPerDwalletError extends Error {
  constructor(
    public readonly dwalletAddress: string,
    public readonly limit: number,
  ) {
    super(`max ${limit} credentials per dWallet`)
    this.name = 'MaxCredentialsPerDwalletError'
  }
}

export class DuplicateCredentialError extends Error {
  constructor(public readonly credentialIdHash: Uint8Array) {
    super('credential already registered')
    this.name = 'DuplicateCredentialError'
  }
}

export class LastActiveCredentialError extends Error {
  constructor(public readonly dwalletAddress: string) {
    super('cannot revoke the last active recovery method')
    this.name = 'LastActiveCredentialError'
  }
}
