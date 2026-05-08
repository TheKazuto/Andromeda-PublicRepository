/**
 * Helpers for building unsigned Solana transactions in the custody-free
 * pattern. The engine returns base64-encoded compiled message bytes; the
 * caller signs locally and submits via /v1/private-tx/submit (or the
 * gateway equivalent) without ever exposing private keys to the engine.
 */

import {
  appendTransactionMessageInstructions,
  compileTransaction,
  createTransactionMessage,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Instruction,
  type Transaction,
} from '@solana/kit'
import { getCachedBlockhash } from './solana-rpc.js'
import type { Blockhash } from '@solana/kit'

export interface BuildTxResult {
  unsignedTxBase64: string
  recentBlockhash: string
  lastValidBlockHeight: bigint
}

/**
 * Builds a v0 (versioned) unsigned transaction with the given instructions
 * and fee payer. Uses a cached blockhash (TTL + single-flight) to avoid one
 * RPC roundtrip per transaction build.
 */
export async function buildUnsignedTransaction(input: {
  feePayer: Address
  instructions: readonly Instruction[]
}): Promise<BuildTxResult> {
  const latest = await getCachedBlockhash()
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(input.feePayer, m),
    (m) =>
      setTransactionMessageLifetimeUsingBlockhash(
        {
          blockhash: latest.blockhash as Blockhash,
          lastValidBlockHeight: latest.lastValidBlockHeight,
        },
        m,
      ),
    (m) => appendTransactionMessageInstructions(input.instructions, m),
  )
  const compiled = compileTransaction(message)
  return {
    unsignedTxBase64: encodeTransaction(compiled),
    recentBlockhash: latest.blockhash,
    lastValidBlockHeight: latest.lastValidBlockHeight,
  }
}

function encodeTransaction(tx: Transaction): string {
  return Buffer.from(tx.messageBytes).toString('base64')
}
