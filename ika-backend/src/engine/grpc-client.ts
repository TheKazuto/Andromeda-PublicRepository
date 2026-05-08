import * as grpc from '@grpc/grpc-js'
import { loadSync } from '@grpc/proto-loader'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logger } from '../logger.js'

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
  private client: any | null = null
  private readonly opts: GrpcClientOptions

  constructor(opts: GrpcClientOptions) {
    this.opts = opts
  }

  private ensureClient(): any {
    if (this.client) return this.client
    let pkg: any
    try {
      const def = loadSync(PROTO_PATH, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      })
      pkg = grpc.loadPackageDefinition(def)
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

  private buildDeadline(): grpc.Metadata extends never ? never : Date {
    const seconds = this.opts.deadlineSeconds ?? DEFAULT_DEADLINE_SECONDS
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

  private async unaryWithRetry<TReq, TResp>(
    method: string,
    req: TReq,
    invoke: (client: any, req: TReq, cb: (err: Error | null, resp: TResp) => void) => void,
    retryableCodes: ReadonlySet<number> = READ_RETRYABLE_CODES,
  ): Promise<TResp> {
    const max = this.opts.maxRetries ?? DEFAULT_MAX_RETRIES
    let lastErr: unknown = null
    for (let attempt = 0; attempt <= max; attempt += 1) {
      try {
        return await new Promise<TResp>((resolve, reject) => {
          const client = this.ensureClient()
          // Each call carries its own deadline so a slow call cannot hang the request.
          const deadline = this.buildDeadline()
          // grpc-js accepts deadline as an option object on the metadata-less variant.
          ;(client[method] as Function).call(
            client,
            req,
            { deadline } as grpc.CallOptions,
            (err: Error | null, resp: TResp) => {
              if (err) reject(err)
              else resolve(resp)
            },
          )
        })
      } catch (err) {
        lastErr = err
        if (attempt >= max || !this.isRetryable(err, retryableCodes)) break
        // Exponential backoff with jitter: 100ms, 250ms, 600ms…
        const base = 100 * Math.pow(2.5, attempt)
        const jitter = Math.random() * 50
        await new Promise((r) => setTimeout(r, base + jitter))
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('gRPC call failed')
  }

  async submitTransaction(req: UserSignedRequestWire): Promise<TransactionResponseWire> {
    return this.unaryWithRetry(
      'SubmitTransaction',
      req,
      (c, r, cb) => c.SubmitTransaction(r, cb),
      SUBMIT_RETRYABLE_CODES,
    )
  }

  async getPresigns(userPubkey: Uint8Array): Promise<PresignInfoWire[]> {
    const resp = await this.unaryWithRetry<{ user_pubkey: Uint8Array }, { presigns?: PresignInfoWire[] }>(
      'GetPresigns',
      { user_pubkey: userPubkey },
      (c, r, cb) => c.GetPresigns(r, cb),
    )
    return resp.presigns ?? []
  }

  async getPresignsForDWallet(userPubkey: Uint8Array, dwalletId: Uint8Array): Promise<PresignInfoWire[]> {
    const resp = await this.unaryWithRetry<
      { user_pubkey: Uint8Array; dwallet_id: Uint8Array },
      { presigns?: PresignInfoWire[] }
    >(
      'GetPresignsForDWallet',
      { user_pubkey: userPubkey, dwallet_id: dwalletId },
      (c, r, cb) => c.GetPresignsForDWallet(r, cb),
    )
    return resp.presigns ?? []
  }

  /** Health probe via grpc.health.v1 (if validator network exposes it). */
  async healthCheck(timeoutMs = 2_000): Promise<boolean> {
    return await new Promise<boolean>((resolve) => {
      const deadline = new Date(Date.now() + timeoutMs)
      try {
        const c = this.ensureClient()
        const fn = (c as Record<string, unknown>).Check
        if (typeof fn !== 'function') {
          resolve(true) // server doesn't expose Health — assume reachable if channel established
          return
        }
        ;(fn as Function).call(c, {}, { deadline }, (err: Error | null) => resolve(!err))
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
