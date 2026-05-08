import { Router } from 'express'
import { ok } from '../types.js'
import { getPool } from '../store/pool.js'
import { logger } from '../logger.js'
import { requireAdminApiKey } from './auth.js'
import type { AppConfig } from '../config.js'
import { getIkaGrpcClient } from '../engine/grpc-client.js'
import { getSolanaRpc } from '../engine/solana-rpc.js'

const DEEP_HEALTH_CACHE_MS = 3_000

interface CheckResult {
  ok: boolean
  detail?: string
  latencyMs?: number
}

interface DeepHealthBody {
  ok: boolean
  checks: {
    postgres: CheckResult
    ikaGrpc: CheckResult
    solanaRpc: CheckResult
  }
}

let deepHealthCache: { expiresAt: number; status: number; body: DeepHealthBody } | null = null

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | null = null
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout after ${ms}ms`)), ms)
  })
  try {
    return await Promise.race([p, timeout])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function checkPostgres(): Promise<CheckResult> {
  const start = Date.now()
  try {
    await withTimeout(getPool().query('SELECT 1'), 2_000)
    return { ok: true, latencyMs: Date.now() - start }
  } catch (err) {
    logger.error({ err }, 'health/deep postgres failed')
    return { ok: false, detail: 'unreachable', latencyMs: Date.now() - start }
  }
}

async function checkIkaGrpc(): Promise<CheckResult> {
  const start = Date.now()
  try {
    const client = getIkaGrpcClient()
    const ok = await withTimeout(client.healthCheck(2_000), 3_000)
    return { ok, latencyMs: Date.now() - start, ...(ok ? {} : { detail: 'health check failed' }) }
  } catch (err) {
    return {
      ok: false,
      detail: err instanceof Error ? err.message : 'unreachable',
      latencyMs: Date.now() - start,
    }
  }
}

async function checkSolanaRpc(): Promise<CheckResult> {
  const start = Date.now()
  try {
    const slot = await withTimeout(getSolanaRpc().getSlot().send(), 3_000)
    return { ok: true, detail: `slot=${slot}`, latencyMs: Date.now() - start }
  } catch (err) {
    return {
      ok: false,
      detail: err instanceof Error ? err.message : 'unreachable',
      latencyMs: Date.now() - start,
    }
  }
}

export function buildHealthRouter(_config: AppConfig): Router {
  const router = Router()

  router.get('/health', (_req, res) => {
    res.json(ok({ status: 'ok', service: 'ika-backend', version: '0.1.0' }))
  })

  router.get('/health/deep', requireAdminApiKey, async (_req, res) => {
    const now = Date.now()
    if (deepHealthCache && deepHealthCache.expiresAt > now) {
      res.status(deepHealthCache.status).json(ok(deepHealthCache.body))
      return
    }
    const [postgres, ikaGrpc, solanaRpc] = await Promise.all([
      checkPostgres(),
      checkIkaGrpc(),
      checkSolanaRpc(),
    ])
    const checks = { postgres, ikaGrpc, solanaRpc }
    const allOk = Object.values(checks).every((c) => c.ok)
    const status = allOk ? 200 : 503
    const body = { ok: allOk, checks }
    deepHealthCache = { expiresAt: now + DEEP_HEALTH_CACHE_MS, status, body }
    res.status(status).json(ok(body))
  })

  return router
}
