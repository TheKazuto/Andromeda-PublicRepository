/**
 * Gas-sponsor signer for the encrypt-backend.
 *
 * **STATUS (2026-05-07): infrastructure ready, NOT yet wired to endpoints.**
 *
 * The Encrypt program upstream (`encrypt-pre-alpha`) requires the `authority`
 * account of `create_input_ciphertext` and similar instructions to be a real
 * Solana transaction signer. Pure gas-sponsoring (gateway pays + signs while
 * user signs only an off-chain challenge) cannot satisfy that constraint
 * without one of:
 *   1. an Andromeda intermediate program (`encrypt-proxy`) that validates a
 *      user challenge via `andromeda_auth` and CPIs the Encrypt program with
 *      a per-user `cpi_authority` PDA, OR
 *   2. an upstream change in the Encrypt program to accept challenge-based
 *      authority (same pattern as `rules-policy` v2).
 *
 * For now the encrypt-backend keeps the legacy `prepare → client signs →
 * submit` flow. This module is kept as ready infra so we can flip the
 * endpoints to gas-sponsored as soon as either path 1 or 2 lands.
 *
 * Once active, Andromeda is wallet-agnostic — users never need a Solana
 * wallet. The encrypt-backend signs and pays for every Solana transaction it
 * builds using a single keypair stored in `ANDROMEDA_GAS_SPONSOR_KEYPAIR`.
 * The fee payer of every tx is `getGasSponsorAddress()`.
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
  type Instruction,
  type KeyPairSigner,
} from '@solana/kit';
import {
  getSetComputeUnitLimitInstruction,
  getSetComputeUnitPriceInstruction,
} from '@solana-program/compute-budget';
import { rpc } from '../solana/connection.js';
import { config } from '../config.js';
import { Errors } from './errors.js';
import { logger } from './logger.js';
import { withTimeout } from './timeout.js';
import { prefetchBlockhash } from '../solana/instructions.js';

let cachedSigner: KeyPairSigner | null = null;

// P0.5 (encrypt-backend mirror of ika-backend gas-sponsor.ts):
// per-fee-payer serialisation. Two concurrent gas-sponsored sends for
// the same fee payer race on the balance check and risk duplicate-
// signature submits if instructions collide. Promise-chain map keyed
// by fee-payer address; queue cap protects from runaway clients.
const GAS_SPONSOR_QUEUE_MAX = Number(process.env.ANDROMEDA_GAS_SPONSOR_QUEUE_MAX ?? '50');
const queueChain = new Map<string, Promise<unknown>>();
const queueDepth = new Map<string, number>();

export class GasSponsorBackpressureError extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super('Gas sponsor queue is full');
    this.retryAfterSeconds = retryAfterSeconds;
    this.name = 'GasSponsorBackpressureError';
  }
}

export function isGasSponsorBackpressure(err: unknown): err is GasSponsorBackpressureError {
  return err instanceof GasSponsorBackpressureError;
}

async function withFeePayerLock<T>(addr: string, fn: () => Promise<T>): Promise<T> {
  // Avoid importing metrics at the top of the file (circular risk with
  // breaker → metrics). Lazy require keeps the module graph DAG clean.
  const m = await import('./metrics.js');
  const depth = (queueDepth.get(addr) ?? 0) + 1;
  if (depth > GAS_SPONSOR_QUEUE_MAX) {
    m.gasSponsorRejectedTotal.labels(addr).inc();
    throw new GasSponsorBackpressureError(Math.min(30, Math.ceil(depth / 10)));
  }
  queueDepth.set(addr, depth);
  m.gasSponsorQueueDepth.labels(addr).set(depth);

  const enqueuedAt = process.hrtime.bigint();
  const prev = (queueChain.get(addr) ?? Promise.resolve()) as Promise<unknown>;
  const release = prev.then(
    () => undefined,
    () => undefined,
  );
  let resolveSlot!: () => void;
  const slot = new Promise<void>((r) => {
    resolveSlot = r;
  });
  queueChain.set(addr, slot);

  try {
    await release;
    const waited = Number(process.hrtime.bigint() - enqueuedAt) / 1e9;
    m.gasSponsorQueueWait.labels(addr).observe(waited);
    return await fn();
  } finally {
    const after = (queueDepth.get(addr) ?? 1) - 1;
    if (after <= 0) {
      queueDepth.delete(addr);
    } else {
      queueDepth.set(addr, after);
    }
    m.gasSponsorQueueDepth.labels(addr).set(Math.max(after, 0));
    resolveSlot();
    if (queueChain.get(addr) === slot) {
      queueChain.delete(addr);
    }
  }
}

/**
 * Loads a Solana keypair from a `solana-keygen` JSON byte array (64 bytes:
 * 32 secret + 32 public). Call once at boot.
 */
export async function initGasSponsor(keypairJson: string): Promise<KeyPairSigner> {
  let arr: unknown;
  try {
    arr = JSON.parse(keypairJson);
  } catch {
    throw new Error('Gas sponsor keypair must be a JSON byte array');
  }
  if (!Array.isArray(arr) || arr.some((b) => typeof b !== 'number')) {
    throw new Error('Gas sponsor keypair must be an array of bytes');
  }
  const bytes = Uint8Array.from(arr as number[]);
  if (bytes.length !== 64) {
    throw new Error(`Gas sponsor keypair must be 64 bytes (got ${bytes.length})`);
  }
  cachedSigner = await createKeyPairSignerFromBytes(bytes);
  logger.info({ address: cachedSigner.address }, 'Encrypt gas sponsor initialized');
  return cachedSigner;
}

export function getGasSponsor(): KeyPairSigner {
  if (!cachedSigner) {
    throw new Error('Gas sponsor not initialized — set ANDROMEDA_GAS_SPONSOR_KEYPAIR');
  }
  return cachedSigner;
}

export function getGasSponsorAddress(): Address {
  return getGasSponsor().address;
}

export type SignAndSendOptions = {
  computeUnitLimit?: number;
  computeUnitPriceMicroLamports?: bigint;
  skipPreflight?: boolean;
};

/**
 * Builds a v0 transaction with the gas sponsor as fee payer, signs it, sends
 * it via Solana RPC, and returns `{ txSignature, recentBlockhash, lastValidBlockHeight }`.
 *
 * Use this for every endpoint that previously returned `unsignedTx` — the
 * caller is no longer responsible for signing or paying.
 */
export async function signAndSendInstructions(
  instructions: Instruction[],
  opts: SignAndSendOptions = {},
): Promise<{
  txSignature: string;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
}> {
  const signer = getGasSponsor();
  const feePayer = String(signer.address);
  return withFeePayerLock(feePayer, () => runSignAndSendLocked(instructions, opts));
}

async function runSignAndSendLocked(
  instructions: Instruction[],
  opts: SignAndSendOptions,
): Promise<{
  txSignature: string;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
}> {
  const signer = getGasSponsor();
  const latest = await prefetchBlockhash();

  const computeIxs: Instruction[] = [];
  if (opts.computeUnitLimit) {
    computeIxs.push(getSetComputeUnitLimitInstruction({ units: opts.computeUnitLimit }));
  }
  const priorityFee =
    opts.computeUnitPriceMicroLamports !== undefined
      ? opts.computeUnitPriceMicroLamports
      : BigInt(config.SOLANA_DEFAULT_PRIORITY_FEE_MICROLAMPORTS);
  if (priorityFee > 0n) {
    computeIxs.push(getSetComputeUnitPriceInstruction({ microLamports: priorityFee }));
  }

  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(signer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latest, m),
    (m) => appendTransactionMessageInstructions([...computeIxs, ...instructions], m),
  );

  const signed = await signTransactionMessageWithSigners(message);
  const wire = getBase64EncodedWireTransaction(signed);

  try {
    const sig = await withTimeout(
      rpc
        .sendTransaction(wire as unknown as Parameters<typeof rpc.sendTransaction>[0], {
          encoding: 'base64',
          skipPreflight: opts.skipPreflight ?? false,
          preflightCommitment: 'confirmed',
        })
        .send(),
      config.SOLANA_RPC_TIMEOUT_MS,
      'sendTransaction timed out',
    );
    return {
      txSignature: sig,
      recentBlockhash: latest.blockhash,
      lastValidBlockHeight: latest.lastValidBlockHeight,
    };
  } catch (err) {
    throw Errors.solanaRpc('failed to submit gas-sponsored transaction', err);
  }
}
