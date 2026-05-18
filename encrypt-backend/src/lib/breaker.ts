/**
 * Tiny in-memory circuit breaker — mirror of ika-backend/src/engine/breaker.ts.
 *
 * Used here to wrap Solana RPC calls (sendTransaction, getLatestBlockhash)
 * so an RPC outage doesn't pile up timed-out requests. The trip/cooldown
 * thresholds match the ika-backend copy for operational consistency.
 *
 * State machine:
 *   closed   → normal flow. Failures increment counters.
 *   open     → all calls fail-fast with CircuitOpenError until cooldown.
 *   half-open → one probe call allowed; success closes, failure re-opens.
 */

type State = 'closed' | 'open' | 'half-open'

const WINDOW_MS = 60_000
const COOLDOWN_MS = 30_000
const CONSECUTIVE_FAILURES = 5
const MIN_REQUESTS_FOR_RATIO = 20
const FAILURE_RATIO_THRESHOLD = 0.5

interface BreakerEntry {
  state: State
  consecutiveFailures: number
  windowStart: number
  windowFailures: number
  windowRequests: number
  openedAt: number
  halfOpenInflight: boolean
}

const breakers = new Map<string, BreakerEntry>()

export class CircuitOpenError extends Error {
  readonly retryAfterSeconds: number
  readonly key: string
  constructor(key: string, retryAfterSeconds: number) {
    super(`circuit open for ${key}`)
    this.name = 'CircuitOpenError'
    this.key = key
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export function isCircuitOpen(err: unknown): err is CircuitOpenError {
  return err instanceof CircuitOpenError
}

function get(key: string): BreakerEntry {
  let e = breakers.get(key)
  if (!e) {
    e = {
      state: 'closed',
      consecutiveFailures: 0,
      windowStart: Date.now(),
      windowFailures: 0,
      windowRequests: 0,
      openedAt: 0,
      halfOpenInflight: false,
    }
    breakers.set(key, e)
  }
  return e
}

export function preCall(key: string): void {
  const e = get(key)
  if (e.state === 'closed') return
  const now = Date.now()
  if (e.state === 'open') {
    const elapsed = now - e.openedAt
    if (elapsed < COOLDOWN_MS) {
      throw new CircuitOpenError(key, Math.ceil((COOLDOWN_MS - elapsed) / 1000))
    }
    e.state = 'half-open'
    e.halfOpenInflight = false
  }
  if (e.state === 'half-open') {
    if (e.halfOpenInflight) {
      throw new CircuitOpenError(key, Math.ceil(COOLDOWN_MS / 1000))
    }
    e.halfOpenInflight = true
  }
}

export function recordSuccess(key: string): void {
  const e = get(key)
  const now = Date.now()
  if (now - e.windowStart >= WINDOW_MS) {
    e.windowStart = now
    e.windowFailures = 0
    e.windowRequests = 0
  }
  e.windowRequests++
  e.consecutiveFailures = 0
  if (e.state === 'half-open') {
    e.state = 'closed'
    e.halfOpenInflight = false
  }
}

export function recordFailure(key: string): void {
  const e = get(key)
  const now = Date.now()
  if (now - e.windowStart >= WINDOW_MS) {
    e.windowStart = now
    e.windowFailures = 0
    e.windowRequests = 0
  }
  e.windowRequests++
  e.windowFailures++
  e.consecutiveFailures++

  if (e.state === 'half-open') {
    e.state = 'open'
    e.openedAt = now
    e.halfOpenInflight = false
    return
  }
  if (e.state !== 'open') {
    const tripByConsecutive = e.consecutiveFailures >= CONSECUTIVE_FAILURES
    const tripByRatio =
      e.windowRequests >= MIN_REQUESTS_FOR_RATIO &&
      e.windowFailures / e.windowRequests >= FAILURE_RATIO_THRESHOLD
    if (tripByConsecutive || tripByRatio) {
      e.state = 'open'
      e.openedAt = now
    }
  }
}

export function getState(key: string): State {
  return get(key).state
}
