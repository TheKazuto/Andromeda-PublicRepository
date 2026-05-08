import { getPool, query } from '../store/pool.js'

/**
 * Postgres-backed state for the Discovery flow only.
 *
 * Quorum sessions and policy state are now sourced directly on-chain (PDA
 * staging in `rules-policy` v2). The legacy `recovery_quorum_sessions`,
 * `recovery_quorum_contributions`, `recovery_rules_policy_state`,
 * `recovery_signing_ledger` and `recovery_gas_ledger` tables are kept for
 * audit / future caching but are no longer written to from the engine.
 */

export interface ChallengeRow {
  nonce: string
  app_id: string
  scheme: string
  wallet_address: string
  message: string
  expires_at: Date
  consumed_at: Date | null
  created_at: Date
}

export async function insertChallenge(input: {
  nonce: string
  appId: string
  scheme: string
  walletAddress: string
  message: string
  expiresAt: Date
}): Promise<void> {
  await query(
    `INSERT INTO recovery_challenges(nonce, app_id, scheme, wallet_address, message, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [input.nonce, input.appId, input.scheme, input.walletAddress, input.message, input.expiresAt],
  )
}

/**
 * Atomic single-use consume. Returns the row only if it was unconsumed
 * AND not expired at SELECT time. Concurrent calls cannot both succeed.
 */
export async function consumeChallenge(nonce: string): Promise<ChallengeRow | null> {
  const result = await getPool().query<ChallengeRow>({
    name: 'recovery_challenge_consume',
    text: `UPDATE recovery_challenges
             SET consumed_at = NOW()
             WHERE nonce = $1 AND consumed_at IS NULL AND expires_at > NOW()
             RETURNING nonce, app_id, scheme, wallet_address, message, expires_at, consumed_at, created_at`,
    values: [nonce],
  })
  return result.rows[0] ?? null
}
