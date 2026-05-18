import * as grpc from '@grpc/grpc-js'
import { loadSync } from '@grpc/proto-loader'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logger } from '../logger.js'
import {
  grpcBreakerState,
  grpcBreakerTripsTotal,
  grpcCallDuration,
  grpcCallTotal,
  grpcRetries,
} from '../metrics.js'
import {
  GrpcCircuitOpenError,
  getBreakerState,
  preCall,
  recordFailure,
  recordSuccess,
} from './breaker.js'

export { GrpcCircuitOpenError, isGrpcCircuitOpen } from './breaker.js'

// Per-method deadlines. Reads use a tight 10s cap; submits keep the
// existing 30s to accommodate MPC ceremonies. Operators can override
// individual methods via env (IKA_GRPC_DEADLINE_<METHOD>_SEC).
const DEFAULT_READ_DEADLINE_SECONDS = 10
const DEFAULT_SUBMIT_DEADLINE_SECONDS = 30

function methodDeadlineSeconds(method: string, fallback: number): number {
  const envKey = `IKA_GRPC_DEADLINE_${method.toUpperCase()}_SEC`
  const v = process.env[envKey]
  if (v) {
    const n = Number(v)
    if (Number.isFinite(n) && n > 0) return n
  }
  return fallback
}

function stateToFloat(s: 'closed' | 'open' | 'half-open'): number {
  return s === 'open' ? 1 : s === 'half-open' ? 2 : 0
}

/**
 * Thin wrapper around the Ika dWallet gRPC service.
 *
 * Surface (per docs at https://solana-pre-alpha.ika.xyz/):
 *   service DWalletService {
 *     rpc SubmitTransaction(UserSignedRequest) returns (TransactionResponse);
 *     rpc GetPresigns(GetPresignsRequest) returns (GetPresignsResponse);
 *     rpc GetPresignsForDWallet(GetPresignsForDWalletRequest) returns (GetPresignsResponse);
 *   }
 *
 * Proto files MUST be copied from `github.com/dwallet-labs/ika-pre-alpha/proto/`
 * into `proto/` at this repo root. The build pipeline does not regenerate them
 * from upstream — pin the version explicitly.
 */

const __dirname = dirname(fileURLToPath(import.meta.url))
const PROTO_PATH = join(__dirname, '../../proto/ika_dwallet.proto')

export interface UserSignedRequestWire {
  user_signature: Uint8Array
  signed_request_data: Uint8Array
}

export interface TransactionResponseWire {
  response_data: Uint8Array
}

export interface PresignInfoWire {
  presign_id: Uint8Array
  dwallet_id: Uint8Array
  curve: number
  signature_scheme: number
  epoch: bigint
}

interface PresignsResponseWire {
  presigns?: PresignInfoWire[]
}

type UnaryCallback<TResp> = (err: grpc.ServiceError | null, resp: TResp) => void

// Minimal structural view of the gRPC service stub `@grpc/proto-loader` builds.
// We only call the methods we declare here; `waitForReady` / `close` / `Check`
// are optional because they depend on the grpc-js version / server features.
interface DWalletServiceClient {
  SubmitTransaction(req: UserSignedRequestWire, options: grpc.CallOptions, cb: UnaryCallback<TransactionResponseWire>): void
  GetPresigns(req: { user_pubkey: Uint8Array }, options: grpc.CallOptions, cb: UnaryCallback<PresignsResponseWire>): void
  GetPresignsForDWallet(
    req: { user_pubkey: Uint8Array; dwallet_id: Uint8Array },
    options: grpc.CallOptions,
    cb: UnaryCallback<PresignsResponseWire>,
  ): void
  waitForReady?(deadline: Date, cb: (err: Error | null) => void): void
  close?(): void
  Check?(req: object, options: grpc.CallOptions, cb: (err: Error | null) => void): void
}

interface DWalletServiceCtor {
  new (address: string, creds: grpc.ChannelCredentials, options?: grpc.ChannelOptions): DWalletServiceClient
}

interface GrpcPackage {
  ika?: { dwallet?: { v1?: { DWalletService?: DWalletServiceCtor } }; DWalletService?: DWalletServiceCtor }
  DWalletService?: DWalletServiceCtor
}

export interface GrpcClientOptions {
  url: string
  tls: boolean
  /** Per-call deadline in seconds. Default: 30s. */
  deadlineSeconds?: number
  /** Number of retry attempts on UNAVAILABLE/DEADLINE_EXCEEDED. Default: 2. */
  maxRetries?: number
}

const READ_RETRYABLE_CODES = new Set<number>([
  grpc.status.UNAVAILABLE,
  grpc.status.DEADLINE_EXCEEDED,
  grpc.status.RESOURCE_EXHAUSTED,
])
const SUBMIT_RETRYABLE_CODES = new Set<number>([grpc.status.UNAVAILABLE])

const DEFAULT_DEADLINE_SECONDS = 30
const DEFAULT_MAX_RETRIES = 2

export class IkaGrpcClient {
  private client: DWalletServiceClient | null = null
  private readonly opts: GrpcClientOptions

  constructor(opts: GrpcClientOptions) {
    this.opts = opts
  }

  private ensureClient(): DWalletServiceClient {
    if (this.client) return this.client
    let pkg: GrpcPackage
    try {
      const def = loadSync(PROTO_PATH, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      })
      pkg = grpc.loadPackageDefinition(def) as unknown as GrpcPackage
    } catch (err) {
      logger.warn({ err, path: PROTO_PATH }, 'proto file missing — gRPC client in stub mode')
      throw new Error(
        'Ika .proto definitions not found. Copy github.com/dwallet-labs/ika-pre-alpha/proto/ into proto/.',
      )
    }
    const ServiceCtor =
      pkg.ika?.dwallet?.v1?.DWalletService ??
      pkg.ika?.DWalletService ??
      pkg.DWalletService
    if (!ServiceCtor) throw new Error('DWalletService not found in proto package')
    const url = this.opts.url.replace(/^https?:\/\//, '')
    const creds = this.opts.tls ? grpc.credentials.createSsl() : grpc.credentials.createInsecure()
    // Channel options: keepalive prevents idle-connection resets from the
    // validator network; reconnect backoff caps tail latency on flap.
    const channelOptions: grpc.ChannelOptions = {
      'grpc.keepalive_time_ms': 30_000,
      'grpc.keepalive_timeout_ms': 10_000,
      'grpc.keepalive_permit_without_calls': 1,
      'grpc.http2.max_pings_without_data': 0,
      'grpc.http2.min_time_between_pings_ms': 10_000,
      'grpc.initial_reconnect_backoff_ms': 1_000,
      'grpc.max_reconnect_backoff_ms': 5_000,
      'grpc.max_receive_message_length': 16 * 1024 * 1024,
      'grpc.max_send_message_length': 16 * 1024 * 1024,
    }
    this.client = new ServiceCtor(url, creds, channelOptions)
    return this.client
  }

  private buildDeadline(deadlineSeconds?: number): grpc.Metadata extends never ? never : Date {
    const seconds = deadlineSeconds ?? this.opts.deadlineSeconds ?? DEFAULT_DEADLINE_SECONDS
    return new Date(Date.now() + seconds * 1000)
  }

  warmup(): void {
    this.ensureClient()
  }

  async waitForReady(timeoutMs = 2_000): Promise<boolean> {
    const client = this.ensureClient()
    const deadline = new Date(Date.now() + timeoutMs)
    return await new Promise<boolean>((resolve) => {
      if (typeof client.waitForReady !== 'function') {
        resolve(true)
        return
      }
      client.waitForReady(deadline, (err: Error | null) => resolve(!err))
    })
  }

  private isRetryable(err: unknown, retryableCodes: ReadonlySet<number>): boolean {
    if (!err || typeof err !== 'object') return false
    const code = (err as { code?: number }).code
    return typeof code === 'number' && retryableCodes.has(code)
  }

  private async unaryWithRetry<TResp>(
    method: string,
    call: (client: DWalletServiceClient, options: grpc.CallOptions, cb: UnaryCallback<TResp>) => void,
    retryableCodes: ReadonlySet<number> = READ_RETRYABLE_CODES,
    deadlineSeconds?: number,
  ): Promise<TResp> {
    const max = this.opts.maxRetries ?? DEFAULT_MAX_RETRIES
    let lastErr: unknown = null
    const startedAt = process.hrtime.bigint()

    // Fail fast when the breaker is open. The throw skips retries because
    // a 30s cooldown is much longer than backoff would wait.
    try {
      preCall(method)
    } catch (err) {
      if (err instanceof GrpcCircuitOpenError) {
        grpcBreakerState.labels(method).set(stateToFloat(getBreakerState(method)))
        grpcCallTotal.labels(method, 'circuit_open').inc()
      }
      throw err
    }
    const stateBefore = getBreakerState(method)

    for (let attempt = 0; attempt <= max; attempt += 1) {
      if (attempt > 0) grpcRetries.labels(method).inc()
      try {
        const resp = await new Promise<TResp>((resolve, reject) => {
          const client = this.ensureClient()
          // Each call carries its own deadline so a slow call cannot hang the request.
          const deadline = this.buildDeadline(deadlineSeconds)
          call(client, { deadline }, (err, response) => {
            if (err) reject(err)
            else resolve(response)
          })
        })
        const elapsed = Number(process.hrtime.bigint() - startedAt) / 1e9
        grpcCallDuration.labels(method, 'ok').observe(elapsed)
        grpcCallTotal.labels(method, 'ok').inc()
        recordSuccess(method)
        grpcBreakerState.labels(method).set(stateToFloat(getBreakerState(method)))
        return resp
      } catch (err) {
        lastErr = err
        if (attempt >= max || !this.isRetryable(err, retryableCodes)) break
        // Exponential backoff with jitter: 100ms, 250ms, 600ms…
        const base = 100 * Math.pow(2.5, attempt)
        const jitter = Math.random() * 50
        await new Promise((r) => setTimeout(r, base + jitter))
      }
    }
    const elapsed = Number(process.hrtime.bigint() - startedAt) / 1e9
    const outcome = grpcOutcome(lastErr)
    grpcCallDuration.labels(method, outcome).observe(elapsed)
    grpcCallTotal.labels(method, outcome).inc()
    recordFailure(method)
    const stateAfter = getBreakerState(method)
    grpcBreakerState.labels(method).set(stateToFloat(stateAfter))
    if (stateBefore !== 'open' && stateAfter === 'open') {
      grpcBreakerTripsTotal.labels(method).inc()
      logger.warn({ method }, 'gRPC circuit breaker tripped open')
    }
    throw lastErr instanceof Error ? lastErr : new Error('gRPC call failed')
  }

  async submitTransaction(req: UserSignedRequestWire): Promise<TransactionResponseWire> {
    return this.unaryWithRetry<TransactionResponseWire>(
      'SubmitTransaction',
      (c, opts, cb) => c.SubmitTransaction(req, opts, cb),
      SUBMIT_RETRYABLE_CODES,
      methodDeadlineSeconds('SubmitTransaction', DEFAULT_SUBMIT_DEADLINE_SECONDS),
    )
  }

  async getPresigns(userPubkey: Uint8Array): Promise<PresignInfoWire[]> {
    const resp = await this.unaryWithRetry<PresignsResponseWire>(
      'GetPresigns',
      (c, opts, cb) => c.GetPresigns({ user_pubkey: userPubkey }, opts, cb),
      READ_RETRYABLE_CODES,
      methodDeadlineSeconds('GetPresigns', DEFAULT_READ_DEADLINE_SECONDS),
    )
    return resp.presigns ?? []
  }

  async getPresignsForDWallet(userPubkey: Uint8Array, dwalletId: Uint8Array): Promise<PresignInfoWire[]> {
    const resp = await this.unaryWithRetry<PresignsResponseWire>(
      'GetPresignsForDWallet',
      (c, opts, cb) => c.GetPresignsForDWallet({ user_pubkey: userPubkey, dwallet_id: dwalletId }, opts, cb),
      READ_RETRYABLE_CODES,
      methodDeadlineSeconds('GetPresignsForDWallet', DEFAULT_READ_DEADLINE_SECONDS),
    )
    return resp.presigns ?? []
  }

  /** Health probe via grpc.health.v1 (if validator network exposes it). */
  async healthCheck(timeoutMs = 2_000): Promise<boolean> {
    return await new Promise<boolean>((resolve) => {
      const deadline = new Date(Date.now() + timeoutMs)
      try {
        const c = this.ensureClient()
        if (typeof c.Check !== 'function') {
          resolve(true) // server doesn't expose Health — assume reachable if channel established
          return
        }
        c.Check({}, { deadline }, (err) => resolve(!err))
      } catch {
        resolve(false)
      }
    })
  }

  /** Closes the underlying channel — call from process shutdown. */
  close(): void {
    if (this.client && typeof this.client.close === 'function') {
      try {
        this.client.close()
      } catch {
        /* ignore */
      }
    }
    this.client = null
  }
}

let singleton: IkaGrpcClient | null = null

export function initIkaGrpcClient(opts: GrpcClientOptions): IkaGrpcClient {
  singleton = new IkaGrpcClient(opts)
  singleton.warmup()
  return singleton
}

export function getIkaGrpcClient(): IkaGrpcClient {
  if (!singleton) throw new Error('Ika gRPC client not initialized')
  return singleton
}

export function closeIkaGrpcClient(): void {
  if (singleton) {
    singleton.close()
    singleton = null
  }
}

// grpcOutcome maps a gRPC error to a coarse Prometheus label. Keeps
// cardinality bounded to {ok, unavailable, deadline, exhausted, other}.
function grpcOutcome(err: unknown): string {
  if (!err) return 'ok'
  const code = (err as { code?: number }).code
  switch (code) {
    case grpc.status.UNAVAILABLE:
      return 'unavailable'
    case grpc.status.DEADLINE_EXCEEDED:
      return 'deadline'
    case grpc.status.RESOURCE_EXHAUSTED:
      return 'exhausted'
    default:
      return 'other'
  }
}
