/**
 * Tiny in-memory circuit breaker per gRPC method.
 *
 * State machine:
 *   closed   → normal flow. Failures increment counters.
 *   open     → all calls fail-fast with GrpcCircuitOpenError until
 *              cooldown elapses, then move to half-open.
 *   half-open → exactly one probe call is allowed. Success closes the
 *              breaker; failure re-opens with full cooldown.
 *
 * Trip rules (mirror gateway gobreaker defaults):
 *   - 5 consecutive failures, OR
 *   - ≥20 requests in the window AND failure ratio ≥ 50%.
 *
 * The breaker is kept deliberately simple. Anything more sophisticated
 * belongs in a library — but pulling cockatiel/opossum just for the
 * Ika channel is overkill given we already have gobreaker on the
 * gateway side covering the public hot path.
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

export class GrpcCircuitOpenError extends Error {
  readonly retryAfterSeconds: number
  readonly method: string
  constructor(method: string, retryAfterSeconds: number) {
    super(`gRPC circuit open for ${method}`)
    this.name = 'GrpcCircuitOpenError'
    this.method = method
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export function isGrpcCircuitOpen(err: unknown): err is GrpcCircuitOpenError {
  return err instanceof GrpcCircuitOpenError
}

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
  return err instanceof CircuitOpenError || err instanceof GrpcCircuitOpenError
}

/** Generic preCall — throws CircuitOpenError. Same machinery as gRPC preCall. */
export function preCallGeneric(key: string): void {
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

function get(method: string): BreakerEntry {
  let e = breakers.get(method)
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
    breakers.set(method, e)
  }
  return e
}

/**
 * Throws GrpcCircuitOpenError if the breaker is open and cooldown has
 * not elapsed. On entry into half-open, only one probe call is allowed
 * concurrently; further callers see "still open".
 */
export function preCall(method: string): void {
  const e = get(method)
  if (e.state === 'closed') return
  const now = Date.now()
  if (e.state === 'open') {
    const elapsed = now - e.openedAt
    if (elapsed < COOLDOWN_MS) {
      throw new GrpcCircuitOpenError(method, Math.ceil((COOLDOWN_MS - elapsed) / 1000))
    }
    e.state = 'half-open'
    e.halfOpenInflight = false
  }
  if (e.state === 'half-open') {
    if (e.halfOpenInflight) {
      throw new GrpcCircuitOpenError(method, Math.ceil(COOLDOWN_MS / 1000))
    }
    e.halfOpenInflight = true
  }
}

export function recordSuccess(method: string): void {
  const e = get(method)
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

export function recordFailure(method: string): void {
  const e = get(method)
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
    // Probe failed → re-open with fresh cooldown.
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

/** Test/observability helper. */
export function getBreakerState(method: string): State {
  return get(method).state
}
