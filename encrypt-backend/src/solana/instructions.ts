import {
  AccountRole,
  type Address,
  type Blockhash,
  type Instruction,
  pipe,
  createTransactionMessage,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  appendTransactionMessageInstructions,
  compileTransaction,
  getBase64EncodedWireTransaction,
} from '@solana/kit';
import {
  getSetComputeUnitLimitInstruction,
  getSetComputeUnitPriceInstruction,
} from '@solana-program/compute-budget';
import { rpc } from './connection.js';
import { config } from '../config.js';
import { Errors } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { withTimeout } from '../lib/timeout.js';

export type AccountInput = {
  address: Address;
  signer?: boolean;
  writable?: boolean;
};

export function makeInstruction(
  programAddress: Address,
  accounts: AccountInput[],
  data: Uint8Array
): Instruction {
  return {
    programAddress,
    accounts: accounts.map((a) => ({
      address: a.address,
      role: roleFor(a.signer ?? false, a.writable ?? false),
    })),
    data,
  };
}

function roleFor(signer: boolean, writable: boolean): AccountRole {
  if (signer && writable) return AccountRole.WRITABLE_SIGNER;
  if (signer) return AccountRole.READONLY_SIGNER;
  if (writable) return AccountRole.WRITABLE;
  return AccountRole.READONLY;
}

export type BuildTxOptions = {
  feePayer: Address;
  instructions: Instruction[];
  computeUnitLimit?: number;
  computeUnitPriceMicroLamports?: bigint;
};

// -----------------------------------------------------------------------------
// Blockhash micro-cache
// -----------------------------------------------------------------------------
//
// getLatestBlockhash dominates p95 of every /prepare endpoint (HTTPS round
// trip to the Solana RPC). We cache the latest blockhash for a short window
// and singleflight concurrent misses. Blockhashes are valid ~150 slots (~60s);
// a 12s default cache is safely under that horizon.

type CachedBlockhash = {
  blockhash: Blockhash;
  lastValidBlockHeight: bigint;
};

let cachedBlockhash: { value: CachedBlockhash; expiresAt: number } | null = null;
let blockhashInflight: Promise<CachedBlockhash> | null = null;

async function getCachedBlockhash(): Promise<CachedBlockhash> {
  const now = Date.now();
  if (cachedBlockhash && cachedBlockhash.expiresAt > now) {
    return cachedBlockhash.value;
  }
  if (blockhashInflight) return blockhashInflight;

  blockhashInflight = (async () => {
    try {
      const res = await withTimeout(
        rpc.getLatestBlockhash().send(),
        config.SOLANA_RPC_TIMEOUT_MS,
        'getLatestBlockhash timed out'
      );
      const value: CachedBlockhash = {
        blockhash: res.value.blockhash,
        lastValidBlockHeight: res.value.lastValidBlockHeight,
      };
      cachedBlockhash = { value, expiresAt: Date.now() + config.BLOCKHASH_CACHE_TTL_MS };
      return value;
    } catch (err) {
      logger.warn({ err }, 'getLatestBlockhash failed');
      throw Errors.solanaRpc('failed to fetch recent blockhash', err);
    } finally {
      blockhashInflight = null;
    }
  })();

  return blockhashInflight;
}

export function prefetchBlockhash(): Promise<CachedBlockhash> {
  return getCachedBlockhash();
}

const DEFAULT_PRIORITY_FEE = BigInt(config.SOLANA_DEFAULT_PRIORITY_FEE_MICROLAMPORTS);

/**
 * Builds a v0 transaction message and returns the base64-encoded wire format
 * (unsigned). The caller is responsible for signing and submitting it back to
 * /submit. This keeps the encrypt-backend custody-free.
 */
export async function buildUnsignedTransaction(opts: BuildTxOptions): Promise<{
  base64: string;
  feePayer: Address;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
}> {
  const latestBlockhash = await getCachedBlockhash();

  const computeIxs: Instruction[] = [];
  if (opts.computeUnitLimit) {
    computeIxs.push(getSetComputeUnitLimitInstruction({ units: opts.computeUnitLimit }));
  }
  const priorityFee =
    opts.computeUnitPriceMicroLamports !== undefined
      ? opts.computeUnitPriceMicroLamports
      : DEFAULT_PRIORITY_FEE;
  if (priorityFee > 0n) {
    computeIxs.push(getSetComputeUnitPriceInstruction({ microLamports: priorityFee }));
  }

  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(opts.feePayer, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstructions([...computeIxs, ...opts.instructions], tx)
  );

  const compiled = compileTransaction(message);
  const base64 = getBase64EncodedWireTransaction(compiled);

  return {
    base64,
    feePayer: opts.feePayer,
    recentBlockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
  };
}

/**
 * Submits a signed wire-format transaction (base64) and returns the signature.
 */
export async function submitWireTransaction(base64Wire: string, skipPreflight = false) {
  try {
    const signature = await withTimeout(
      rpc
        .sendTransaction(base64Wire as unknown as Parameters<typeof rpc.sendTransaction>[0], {
          encoding: 'base64',
          skipPreflight,
        })
        .send(),
      config.SOLANA_RPC_TIMEOUT_MS,
      'sendTransaction timed out'
    );
    return signature;
  } catch (err) {
    throw Errors.solanaRpc('failed to submit transaction', err);
  }
}
