// Email — Postgres-backed sliding-window rate limit.

import { createHash } from 'node:crypto'
import { getPool } from '../../store/pool.js'

const WINDOW_INTERVAL = "INTERVAL '1 hour'"

export function emailBucketKey(email: string): string {
  return `email:${email}`
}

export function ipBucketKey(ipHash: string): string {
  return `ip:${ipHash}`
}

export function hashIpAddress(ip: string): string {
  return createHash('sha256').update(ip).digest('hex').slice(0, 32)
}

async function countWithinWindow(bucketKey: string): Promise<number> {
  const result = await getPool().query<{ count: string }>(
    `SELECT COALESCE(SUM(count), 0)::TEXT AS count
       FROM ika_identity_email_rate_buckets
       WHERE bucket_key = $1
         AND window_start > NOW() - ${WINDOW_INTERVAL}`,
    [bucketKey],
  )
  return Number.parseInt(result.rows[0]?.count ?? '0', 10)
}

async function recordHit(bucketKey: string): Promise<void> {
  await getPool().query(
    `INSERT INTO ika_identity_email_rate_buckets (bucket_key, window_start, count)
       VALUES ($1, date_trunc('hour', NOW()), 1)
       ON CONFLICT (bucket_key, window_start)
       DO UPDATE SET count = ika_identity_email_rate_buckets.count + 1, updated_at = NOW()`,
    [bucketKey],
  )
}

export interface CheckEmailRateLimitInput {
  email: string
  ipHash: string | null
  limitPerEmail: number
  limitPerIp: number
}

export interface RateLimitDecision {
  allowed: boolean
  reason: 'email' | 'ip' | null
  countsBefore: { email: number; ip: number }
}

export async function checkEmailRateLimit(input: CheckEmailRateLimitInput): Promise<RateLimitDecision> {
  const emailKey = emailBucketKey(input.email)
  const ipKey = input.ipHash ? ipBucketKey(input.ipHash) : null

  const [emailCount, ipCount] = await Promise.all([
    countWithinWindow(emailKey),
    ipKey ? countWithinWindow(ipKey) : Promise.resolve(0),
  ])

  if (emailCount >= input.limitPerEmail) {
    return { allowed: false, reason: 'email', countsBefore: { email: emailCount, ip: ipCount } }
  }
  if (ipKey && ipCount >= input.limitPerIp) {
    return { allowed: false, reason: 'ip', countsBefore: { email: emailCount, ip: ipCount } }
  }
  return { allowed: true, reason: null, countsBefore: { email: emailCount, ip: ipCount } }
}

export async function recordEmailRateHit(email: string, ipHash: string | null): Promise<void> {
  await Promise.all([
    recordHit(emailBucketKey(email)),
    ipHash ? recordHit(ipBucketKey(ipHash)) : Promise.resolve(),
  ])
}

export async function consumeEmailRateLimit(input: CheckEmailRateLimitInput): Promise<RateLimitDecision> {
  const decision = await checkEmailRateLimit(input)
  if (!decision.allowed) return decision
  await recordEmailRateHit(input.email, input.ipHash)
  return decision
}
