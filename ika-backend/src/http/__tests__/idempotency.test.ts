import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createHash } from 'node:crypto'

const sha256Hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex')

// Mock the Postgres pool — the middleware's L2 layer.
const pool = vi.hoisted(() => ({ query: vi.fn() }))
vi.mock('../../store/pool.js', () => ({ getPool: () => pool }))

const { idempotencyMiddleware, REPLAY_HEADER } = await import('../idempotency.js')

// ── Minimal Express req/res doubles ──────────────────────────────
interface FakeReqInit {
  method?: string
  url?: string
  path?: string
  headers?: Record<string, string>
  rawBody?: Buffer
}
function fakeReq(init: FakeReqInit) {
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(init.headers ?? {})) headers[k.toLowerCase()] = v
  const url = init.url ?? init.path ?? '/'
  return {
    method: init.method ?? 'POST',
    originalUrl: url,
    path: init.path ?? (url.split('?')[0] ?? url),
    headers,
    rawBody: init.rawBody ?? Buffer.alloc(0),
    body: undefined,
    header(name: string) {
      return headers[name.toLowerCase()]
    },
  }
}

class FakeRes {
  statusCode = 200
  private _headers: Record<string, string | number> = {}
  body: Buffer = Buffer.alloc(0)
  ended = false
  jsonValue: unknown = undefined
  status(code: number): this {
    this.statusCode = code
    return this
  }
  setHeader(k: string, v: string | number): void {
    this._headers[k.toLowerCase()] = v
  }
  getHeader(k: string): string | number | undefined {
    return this._headers[k.toLowerCase()]
  }
  getHeaders(): Record<string, string | number> {
    return { ...this._headers }
  }
  write(chunk: unknown): boolean {
    const b = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Buffer.from(chunk as Uint8Array)
    this.body = Buffer.concat([this.body, b])
    return true
  }
  end(chunk?: unknown): this {
    if (chunk !== undefined) {
      const b = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Buffer.from(chunk as Uint8Array)
      this.body = Buffer.concat([this.body, b])
    }
    this.ended = true
    return this
  }
  send(buf: Buffer | string): this {
    return this.end(buf)
  }
  json(obj: unknown): this {
    this.setHeader('content-type', 'application/json')
    this.jsonValue = obj
    return this.end(Buffer.from(JSON.stringify(obj), 'utf8'))
  }
}

function runMiddleware(req: ReturnType<typeof fakeReq>, res: FakeRes, downstream: () => void): Promise<void> {
  const next = vi.fn(() => downstream())
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return idempotencyMiddleware()(req as any, res as any, next as any).then(() => {
    // `next` may schedule the downstream synchronously; nothing async needed.
  })
}

const SUBMIT_PATH = '/v1/dwallet/dkg/submit'
const ANON_HEADERS = (idemKey: string, apiKey = 'k1') => ({ 'idempotency-key': idemKey, 'x-api-key': apiKey })

// A row shaped like reserveOrLookup's CTE result when WE win the reservation
// (fresh insert/takeover): did_reserve=true, status in_progress, no response yet.
function reserveWon(requestHash: string) {
  return {
    reservation_id: 'res-' + requestHash.slice(0, 8),
    status: 'in_progress',
    request_hash: requestHash,
    status_code: null,
    response_body: null,
    response_headers: null,
    reservation_until: new Date(Date.now() + 60_000),
    expires_at: new Date(Date.now() + 3_600_000),
    did_reserve: true,
  }
}

describe('http/idempotency middleware', () => {
  beforeEach(() => {
    pool.query.mockReset()
    pool.query.mockResolvedValue({ rows: [] }) // default: L2 miss
  })

  it('passes through non-mutation methods untouched', async () => {
    const req = fakeReq({ method: 'GET', path: '/v1/dwallet/dkg/submit' })
    const res = new FakeRes()
    let called = false
    await runMiddleware(req, res, () => { called = true })
    expect(called).toBe(true)
    expect(res.ended).toBe(false)
  })

  it('returns 428 when a route that requires a key is called without one', async () => {
    const req = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers: { 'x-api-key': 'k1' } })
    const res = new FakeRes()
    await runMiddleware(req, res, () => { throw new Error('downstream should not run') })
    expect(res.statusCode).toBe(428)
    expect((res.jsonValue as { error: { code: string } }).error.code).toBe('idempotency_key_required')
  })

  it('passes through a non-required route with no key', async () => {
    const req = fakeReq({ method: 'POST', path: '/v1/something-else', headers: { 'x-api-key': 'k1' } })
    const res = new FakeRes()
    let called = false
    await runMiddleware(req, res, () => { called = true; res.status(200).json({ ok: true }) })
    expect(called).toBe(true)
  })

  it('rejects an Idempotency-Key that is too short or too long', async () => {
    for (const key of ['short', 'x'.repeat(201)]) {
      const req = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers: { 'idempotency-key': key, 'x-api-key': 'k1' } })
      const res = new FakeRes()
      await runMiddleware(req, res, () => { throw new Error('downstream should not run') })
      expect(res.statusCode).toBe(400)
      expect((res.jsonValue as { error: { code: string } }).error.code).toBe('invalid_idempotency_key')
    }
  })

  it('rejects a body larger than the hash limit', async () => {
    const req = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers: ANON_HEADERS('a'.repeat(16)), rawBody: Buffer.alloc(2 * 1024 * 1024) })
    const res = new FakeRes()
    await runMiddleware(req, res, () => { throw new Error('downstream should not run') })
    expect(res.statusCode).toBe(400)
    expect((res.jsonValue as { error: { code: string } }).error.code).toBe('body_too_large')
  })

  it('fails open if the L2 lookup throws', async () => {
    pool.query.mockRejectedValueOnce(new Error('db down'))
    const req = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers: ANON_HEADERS('failopen-key-1') })
    const res = new FakeRes()
    let called = false
    await runMiddleware(req, res, () => { called = true; res.status(200).json({ ok: true }) })
    expect(called).toBe(true)
  })

  it('finalizes a reserved 2xx, then replays it on a retry with the same body (L1)', async () => {
    const headers = ANON_HEADERS('replay-key-AAAA', 'apiR')
    // first call → we win the reservation (did_reserve:true), downstream returns 200
    pool.query.mockResolvedValueOnce({ rows: [reserveWon(sha256Hex(Buffer.from('{"x":1}')))] })
    const req1 = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"x":1}') })
    const res1 = new FakeRes()
    await runMiddleware(req1, res1, () => { res1.status(200).json({ done: true }) })
    expect(res1.statusCode).toBe(200)
    // The reservation was finalized (UPDATE … status='completed').
    const finalize = pool.query.mock.calls.find(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes("'completed'"),
    )
    expect(finalize).toBeDefined()

    // second call, same key + same body → L1 hit, replay, downstream NOT run
    pool.query.mockClear()
    const req2 = fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"x":1}') })
    const res2 = new FakeRes()
    await runMiddleware(req2, res2, () => { throw new Error('downstream should not run on replay') })
    expect(res2.statusCode).toBe(200)
    expect(res2.getHeader(REPLAY_HEADER)).toBe('true')
    expect(JSON.parse(res2.body.toString())).toEqual({ done: true })
    // L1 hit means no DB round-trip at all.
    expect(pool.query).not.toHaveBeenCalled()
  })

  it('returns 422 when the same key is reused with a different body', async () => {
    const headers = ANON_HEADERS('collide-key-BBBB', 'apiC')
    // first call wins the reservation and completes 200 → caches in L1.
    pool.query.mockResolvedValueOnce({ rows: [reserveWon(sha256Hex(Buffer.from('{"a":1}')))] })
    const res1 = new FakeRes()
    await runMiddleware(fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"a":1}') }), res1, () => { res1.status(200).json({ ok: true }) })
    expect(res1.statusCode).toBe(200)

    // same key, different body → L1 hit with a mismatched request hash → 422.
    const res2 = new FakeRes()
    await runMiddleware(fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"a":2}') }), res2, () => { throw new Error('downstream should not run') })
    expect(res2.statusCode).toBe(422)
    expect((res2.jsonValue as { error: { code: string } }).error.code).toBe('idempotency_collision')
  })

  it('does not persist a 5xx response', async () => {
    const headers = ANON_HEADERS('fivexx-key-CCCC', 'api5')
    const res1 = new FakeRes()
    await runMiddleware(fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"q":1}') }), res1, () => { res1.status(503).json({ error: 'boom' }) })
    expect(res1.statusCode).toBe(503)
    const persistCall = pool.query.mock.calls.find((c) => (c[0] as { name?: string }).name === 'idempotency_persist')
    expect(persistCall).toBeUndefined()

    // retry → not a replay (nothing was cached), downstream runs again
    let ranAgain = false
    const res2 = new FakeRes()
    await runMiddleware(fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"q":1}') }), res2, () => { ranAgain = true; res2.status(200).json({ ok: true }) })
    expect(ranAgain).toBe(true)
  })

  it('replays from the reservation lookup when the key is already completed (not in L1)', async () => {
    const headers = ANON_HEADERS('l2-key-DDDD', 'apiL2')
    // reserveOrLookup finds an existing completed row (did_reserve:false).
    pool.query.mockResolvedValueOnce({
      rows: [
        {
          reservation_id: 'someone-else',
          status: 'completed',
          did_reserve: false,
          status_code: 201,
          response_body: Buffer.from('{"from":"l2"}'),
          response_headers: { 'content-type': 'application/json' },
          request_hash: sha256Hex(Buffer.from('{"z":9}')),
          reservation_until: null,
          expires_at: new Date(Date.now() + 3600_000),
        },
      ],
    })
    const res = new FakeRes()
    await runMiddleware(fakeReq({ method: 'POST', path: SUBMIT_PATH, headers, rawBody: Buffer.from('{"z":9}') }), res, () => { throw new Error('downstream should not run on replay') })
    expect(res.statusCode).toBe(201)
    expect(res.getHeader(REPLAY_HEADER)).toBe('true')
    expect(JSON.parse(res.body.toString())).toEqual({ from: 'l2' })
  })
})
