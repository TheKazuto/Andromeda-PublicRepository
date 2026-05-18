/**
 * Gas-sponsor signer.
 *
 * Andromeda is wallet-agnostic — users sign challenges off-chain with whatever
 * wallet they have (EVM / Sui / Bitcoin / Cosmos / Solana / passkey). The
 * Solana transaction itself is signed and paid by a backend-controlled
 * keypair (`ANDROMEDA_GAS_SPONSOR_KEYPAIR`, with legacy alias
 * `IKA_GAS_SPONSOR_KEYPAIR` accepted for back-compat), so the caller never
 * needs SOL or a Solana wallet.
 */

import {
  appendTransactionMessageInstructions,
  createKeyPairSignerFromBytes,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type Blockhash,
  type Instruction,
  type KeyPairSigner,
} from '@solana/kit'

import { classifySolanaRpcError, getCachedBlockhash, getSolanaRpc, invalidateBlockhashCache, withSolanaRpc } from './solana-rpc.js'
import { logger } from '../logger.js'
import { query } from '../store/pool.js'
import {
  gasSponsorBalanceLamports,
  gasSponsorDuplicateSignature,
  gasSponsorDuration,
  gasSponsorLamportsSpent,
  gasSponsorQueueDepth,
  gasSponsorQueueWait,
  gasSponsorRejectedTotal,
  gasSponsorRequestsTotal,
} from '../metrics.js'

// Pool of gas sponsor signers. Index 0 is the primary; subsequent
// signers are used for load distribution when initialised via
// initGasSponsorPool / ANDROMEDA_GAS_SPONSOR_KEYPAIRS. A single-keypair
// deployment keeps `signerPool.length === 1`, preserving the legacy
// behaviour of `getGasSponsor()` / `getGasSponsorAddress()`.
let signerPool: KeyPairSigner[] = []
const CONFIRMATION_TIMEOUT_MS = 30_000
const CONFIRMATION_POLL_MS = 500
const LAMPORTS_PER_SOL = 1_000_000_000

// P0.5: per-fee-payer serialisation. Concurrent gas-sponsored sends for
// the same fee payer cannot overlap or they race on balance checks and
// risk duplicate-signature submits if their tx bytes happen to collide.
// We serialise via a promise chain keyed by fee-payer address and cap
// queue depth so a runaway client can't starve everyone else.
const GAS_SPONSOR_QUEUE_MAX = Number(process.env.ANDROMEDA_GAS_SPONSOR_QUEUE_MAX ?? '50')
const queueChain = new Map<string, Promise<unknown>>()
const queueDepth = new Map<string, number>()

class GasSponsorBackpressureError extends Error {
  readonly retryAfterSeconds: number
  constructor(retryAfterSeconds: number) {
    super('Gas sponsor queue is full')
    this.retryAfterSeconds = retryAfterSeconds
    this.name = 'GasSponsorBackpressureError'
  }
}

export function isGasSponsorBackpressure(err: unknown): err is GasSponsorBackpressureError {
  return err instanceof GasSponsorBackpressureError
}

async function withFeePayerLock<T>(addr: string, fn: () => Promise<T>): Promise<T> {
  const depth = (queueDepth.get(addr) ?? 0) + 1
  if (depth > GAS_SPONSOR_QUEUE_MAX) {
    gasSponsorRejectedTotal.labels(addr).inc()
    // Suggest a retry roughly proportional to the queue depth.
    throw new GasSponsorBackpressureError(Math.min(30, Math.ceil(depth / 10)))
  }
  queueDepth.set(addr, depth)
  gasSponsorQueueDepth.labels(addr).set(depth)

  const enqueuedAt = process.hrtime.bigint()
  const prev = (queueChain.get(addr) ?? Promise.resolve()) as Promise<unknown>
  const release = prev.then(
    () => undefined,
    () => undefined,
  )
  let resolveSlot!: () => void
  const slot = new Promise<void>((r) => {
    resolveSlot = r
  })
  // Next requestor waits until our slot resolves.
  queueChain.set(addr, slot)

  try {
    await release
    const waited = Number(process.hrtime.bigint() - enqueuedAt) / 1e9
    gasSponsorQueueWait.labels(addr).observe(waited)
    return await fn()
  } finally {
    const after = (queueDepth.get(addr) ?? 1) - 1
    if (after <= 0) {
      queueDepth.delete(addr)
    } else {
      queueDepth.set(addr, after)
    }
    gasSponsorQueueDepth.labels(addr).set(Math.max(after, 0))
    resolveSlot()
    if (queueChain.get(addr) === slot) {
      queueChain.delete(addr)
    }
  }
}

interface GasSponsorLimits {
  minBalanceLamports: bigint
  maxGasPerOpLamports: bigint
}

let limits: GasSponsorLimits = {
  minBalanceLamports: 500_000_000n,
  maxGasPerOpLamports: 20_000_000n,
}

function decodeKeypairBytes(keypairJson: string): Uint8Array {
  let arr: unknown
  try {
    arr = JSON.parse(keypairJson)
  } catch {
    throw new Error('Gas sponsor keypair must be a JSON byte array')
  }
  if (!Array.isArray(arr) || arr.some((b) => typeof b !== 'number')) {
    throw new Error('Gas sponsor keypair must be an array of bytes')
  }
  const bytes = Uint8Array.from(arr as number[])
  if (bytes.length !== 64) {
    throw new Error(`Gas sponsor keypair must be 64 bytes (got ${bytes.length})`)
  }
  return bytes
}

/**
 * Single-keypair init. Equivalent to initGasSponsorPool([keypairJson]).
 * Kept for back-compat with existing callers that read
 * ANDROMEDA_GAS_SPONSOR_KEYPAIR.
 */
export async function initGasSponsor(
  keypairJson: string,
  opts: { minBalanceSol?: number; maxGasPerOpLamports?: number } = {},
): Promise<KeyPairSigner> {
  const pool = await initGasSponsorPool([keypairJson], opts)
  // pool[0] is non-undefined because initGasSponsorPool guarantees
  // length >= 1 on success; non-null assertion keeps the legacy
  // return-type intact for callers that already dereference.
  return pool[0]!
}

/**
 * Initialise a pool of N gas-sponsor signers. `signAndSendInstructions`
 * picks the least-loaded signer (smallest fee-payer queue depth) before
 * each tx. Each fee payer keeps its own per-address mutex via
 * withFeePayerLock, so concurrent sends across the pool are fully
 * parallel.
 *
 * Returns the array of signers in the order they were provided. Index 0
 * is the primary — exposed by getGasSponsor() / getGasSponsorAddress()
 * for callers that don't care about the pool.
 */
export async function initGasSponsorPool(
  keypairJsons: string[],
  opts: { minBalanceSol?: number; maxGasPerOpLamports?: number } = {},
): Promise<KeyPairSigner[]> {
  if (keypairJsons.length === 0) {
    throw new Error('initGasSponsorPool requires at least one keypair')
  }
  limits = {
    minBalanceLamports: solToLamports(opts.minBalanceSol ?? 0.5),
    maxGasPerOpLamports: BigInt(opts.maxGasPerOpLamports ?? 20_000_000),
  }
  const signers: KeyPairSigner[] = []
  for (const kp of keypairJsons) {
    const bytes = decodeKeypairBytes(kp)
    signers.push(await createKeyPairSignerFromBytes(bytes))
  }
  // De-duplicate by address (operator typo: same keypair listed twice).
  const seen = new Set<string>()
  const deduped = signers.filter((s) => {
    const addr = String(s.address)
    if (seen.has(addr)) {
      logger.warn({ address: addr }, 'gas sponsor pool: duplicate keypair, skipping')
      return false
    }
    seen.add(addr)
    return true
  })
  signerPool = deduped
  return signerPool
}

export function getGasSponsor(): KeyPairSigner {
  if (signerPool.length === 0) {
    throw new Error('Gas sponsor not initialized — set ANDROMEDA_GAS_SPONSOR_KEYPAIR or ANDROMEDA_GAS_SPONSOR_KEYPAIRS')
  }
  return signerPool[0]!
}

export function getGasSponsorAddress(): Address {
  return getGasSponsor().address
}

export function getGasSponsorPoolAddresses(): Address[] {
  return signerPool.map((s) => s.address)
}

/**
 * Select the next signer from the pool. Strategy: least-depth — the
 * signer whose fee-payer queue currently has the fewest pending +
 * in-flight requests. Ties broken by lowest index for stability.
 *
 * With a single-keypair deployment this collapses to the trivial
 * "return the only signer" path.
 */
function pickSigner(): KeyPairSigner {
  if (signerPool.length === 0) {
    throw new Error('Gas sponsor not initialized')
  }
  if (signerPool.length === 1) {
    return signerPool[0]!
  }
  let best = signerPool[0]!
  let bestDepth = queueDepth.get(String(best.address)) ?? 0
  for (let i = 1; i < signerPool.length; i += 1) {
    const s = signerPool[i]!
    const d = queueDepth.get(String(s.address)) ?? 0
    if (d < bestDepth) {
      best = s
      bestDepth = d
    }
  }
  return best
}

/**
 * Builds a v0 transaction with the gas sponsor as fee payer, signs it,
 * sends it via RPC, and returns the transaction signature.
 *
 * Caller is responsible for ensuring `instructions` is valid (precompiles,
 * main ix, etc).
 */
export async function signAndSendInstructions(
  instructions: Instruction[],
  opKind = 'recovery',
  context: { dwalletAddress?: string; policyAddress?: string; engineAddress?: string } = {},
): Promise<string> {
  // Pick the least-loaded fee payer BEFORE entering the lock so depth
  // observations include this request's slot. Once the address is
  // chosen, the per-fee-payer lock serialises subsequent sends for it.
  const signer = pickSigner()
  const feePayer = String(signer.address)
  return withFeePayerLock(feePayer, () =>
    runSignAndSendLocked(signer, instructions, opKind, context),
  )
}

async function runSignAndSendLocked(
  signer: KeyPairSigner,
  instructions: Instruction[],
  opKind: string,
  context: { dwalletAddress?: string; policyAddress?: string; engineAddress?: string },
): Promise<string> {
  const startedAt = process.hrtime.bigint()
  let outcome = 'submitted'
  try {
    const balanceBefore = await getGasSponsorBalanceLamportsFor(signer.address)
    assertGasSponsorBalance(balanceBefore)

    const latest = await getCachedBlockhash()
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      (m) => setTransactionMessageFeePayerSigner(signer, m),
      (m) =>
        setTransactionMessageLifetimeUsingBlockhash(
          {
            blockhash: latest.blockhash as Blockhash,
            lastValidBlockHeight: latest.lastValidBlockHeight,
          },
          m,
        ),
      (m) => appendTransactionMessageInstructions(instructions, m),
    )
    const signed = await signTransactionMessageWithSigners(message)
    const estimatedFee = await estimateTransactionFeeLamports(signed.messageBytes)
    if (estimatedFee > limits.maxGasPerOpLamports) {
      outcome = 'rejected'
      throw new Error(
        `Gas estimate exceeds max per operation: ${estimatedFee} > ${limits.maxGasPerOpLamports}`,
      )
    }
    if (balanceBefore - estimatedFee < limits.minBalanceLamports) {
      outcome = 'rejected'
      throw new Error('Gas sponsor balance would fall below minimum after this operation')
    }

    const wire = getBase64EncodedWireTransaction(signed)
    try {
      await simulateOrThrow(wire)
    } catch (err) {
      outcome = 'simulation_failed'
      throw err
    }
    let sig: string
    try {
      sig = await withSolanaRpc('sendTransaction', () =>
        getSolanaRpc()
          .sendTransaction(wire, { encoding: 'base64', preflightCommitment: 'confirmed' })
          .send(),
      )
    } catch (err) {
      // duplicate-signature comes back as JSON-RPC -32002 / "already processed";
      // bucket it separately so a retry storm is visible without flooding the
      // generic rpc_error label.
      const msg = String((err as { message?: string }).message ?? err)
      if (/already processed|duplicate/i.test(msg)) {
        gasSponsorDuplicateSignature.inc()
        outcome = 'duplicate_signature'
      } else if (classifySolanaRpcError(err) === 'blockhash_expired') {
        // Blockhash aged out between fetch and send (~12s cache TTL +
        // build time + simulate). Invalidate so the next attempt
        // refetches; never reuse the already-signed wire transaction
        // with a new blockhash — that would invalidate the signature.
        invalidateBlockhashCache()
        outcome = 'blockhash_expired'
      } else {
        outcome = 'rpc_error'
      }
      throw err
    }
    await waitForSignatureConfirmation(sig)
    const balanceAfter = await getGasSponsorBalanceLamportsFor(signer.address)
    // Balance gauge reports the *primary* fee payer's balance so existing
    // dashboards keep working. Per-fee-payer balances are observable via
    // an explicit health endpoint if needed (not implemented).
    if (String(signer.address) === String(signerPool[0]?.address)) {
      gasSponsorBalanceLamports.set(Number(balanceAfter))
    }
    const lamportsPaid = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : estimatedFee
    if (lamportsPaid > limits.maxGasPerOpLamports) {
      logger.error(
        { opKind, txSignature: sig, lamportsPaid: lamportsPaid.toString(), max: limits.maxGasPerOpLamports.toString() },
        'gas sponsor operation exceeded configured max after confirmation',
      )
    }
    gasSponsorLamportsSpent.labels(opKind).inc(Number(lamportsPaid))
    await recordGasLedger({
      opKind,
      lamportsPaid,
      txSignature: sig,
      ...context,
    })
    return sig
  } finally {
    const elapsed = Number(process.hrtime.bigint() - startedAt) / 1e9
    gasSponsorDuration.labels(opKind, outcome).observe(elapsed)
    gasSponsorRequestsTotal.labels(opKind, outcome).inc()
  }
}

function solToLamports(sol: number): bigint {
  return BigInt(Math.ceil(sol * LAMPORTS_PER_SOL))
}

async function getGasSponsorBalanceLamports(): Promise<bigint> {
  return getGasSponsorBalanceLamportsFor(getGasSponsorAddress())
}

async function getGasSponsorBalanceLamportsFor(address: Address): Promise<bigint> {
  const { value } = await getSolanaRpc().getBalance(address, { commitment: 'confirmed' }).send()
  return BigInt(value)
}

function assertGasSponsorBalance(balanceLamports: bigint): void {
  if (balanceLamports < limits.minBalanceLamports) {
    throw new Error('Gas sponsor balance below configured minimum')
  }
}

async function estimateTransactionFeeLamports(messageBytes: ArrayLike<number>): Promise<bigint> {
  const messageBase64 = Buffer.from(messageBytes).toString('base64')
  const { value } = await getSolanaRpc()
    .getFeeForMessage(messageBase64 as never, { commitment: 'confirmed' })
    .send()
  if (value === null) throw new Error('Unable to estimate Solana transaction fee')
  return BigInt(value)
}

// JSON.stringify chokes on bigint; the Solana RPC error/status objects can
// carry u64 fields parsed as bigint by @solana/kit. Stringify those as decimal
// strings so the diagnostic message survives.
function jsonStr(v: unknown): string {
  return JSON.stringify(v, (_k, val) => (typeof val === 'bigint' ? val.toString() : val))
}

async function simulateOrThrow(wireTransactionBase64: string): Promise<void> {
  const { value } = await getSolanaRpc()
    .simulateTransaction(wireTransactionBase64 as never, {
      encoding: 'base64',
      commitment: 'confirmed',
      sigVerify: true,
    })
    .send()
  if (value.err) {
    const logs = Array.isArray(value.logs) ? value.logs.join(' | ') : ''
    throw new Error(
      `Solana transaction simulation failed: ${jsonStr(value.err)}${logs ? ` — logs: ${logs}` : ''}`,
    )
  }
}

async function waitForSignatureConfirmation(signature: string): Promise<void> {
  const startedAt = Date.now()
  while (Date.now() - startedAt < CONFIRMATION_TIMEOUT_MS) {
    const { value } = await getSolanaRpc()
      .getSignatureStatuses([signature as never], { searchTransactionHistory: true })
      .send()
    const status = value[0]
    if (status?.err) {
      const errStr = jsonStr(status.err)
      // BlockhashNotFound / BlockheightExceeded in the status → the
      // transaction will never confirm; invalidate so the next attempt
      // starts with a fresh blockhash.
      if (/blockhash|blockheight/i.test(errStr)) {
        invalidateBlockhashCache()
      }
      throw new Error(`Solana transaction failed: ${errStr}`)
    }
    if (status?.confirmationStatus === 'confirmed' || status?.confirmationStatus === 'finalized') {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, CONFIRMATION_POLL_MS))
  }
  throw new Error('Solana transaction confirmation timeout')
}

async function recordGasLedger(input: {
  opKind: string
  lamportsPaid: bigint
  txSignature: string
  dwalletAddress?: string
  policyAddress?: string
}): Promise<void> {
  try {
    await query(
      `INSERT INTO recovery_gas_ledger
         (dwallet_address, policy_address, op_kind, lamports_paid, tx_signature)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        input.dwalletAddress ?? null,
        input.policyAddress ?? null,
        input.opKind,
        input.lamportsPaid.toString(),
        input.txSignature,
      ],
    )
  } catch (err) {
    logger.warn({ err, opKind: input.opKind, txSignature: input.txSignature }, 'gas ledger persist failed')
  }
}
