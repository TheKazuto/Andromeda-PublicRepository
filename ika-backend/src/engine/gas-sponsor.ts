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

import { getCachedBlockhash, getSolanaRpc } from './solana-rpc.js'
import { logger } from '../logger.js'
import { query } from '../store/pool.js'

let cachedSigner: KeyPairSigner | null = null
const CONFIRMATION_TIMEOUT_MS = 30_000
const CONFIRMATION_POLL_MS = 500
const LAMPORTS_PER_SOL = 1_000_000_000

interface GasSponsorLimits {
  minBalanceLamports: bigint
  maxGasPerOpLamports: bigint
}

let limits: GasSponsorLimits = {
  minBalanceLamports: 500_000_000n,
  maxGasPerOpLamports: 20_000_000n,
}

/**
 * Loads a Solana keypair from a `solana-keygen` JSON array (64 bytes:
 * 32 secret + 32 public).
 */
export async function initGasSponsor(
  keypairJson: string,
  opts: { minBalanceSol?: number; maxGasPerOpLamports?: number } = {},
): Promise<KeyPairSigner> {
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
  limits = {
    minBalanceLamports: solToLamports(opts.minBalanceSol ?? 0.5),
    maxGasPerOpLamports: BigInt(opts.maxGasPerOpLamports ?? 20_000_000),
  }
  cachedSigner = await createKeyPairSignerFromBytes(bytes)
  return cachedSigner
}

export function getGasSponsor(): KeyPairSigner {
  if (!cachedSigner) {
    throw new Error('Gas sponsor not initialized — set ANDROMEDA_GAS_SPONSOR_KEYPAIR')
  }
  return cachedSigner
}

export function getGasSponsorAddress(): Address {
  return getGasSponsor().address
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
  context: { dwalletAddress?: string; policyAddress?: string } = {},
): Promise<string> {
  const signer = getGasSponsor()
  const balanceBefore = await getGasSponsorBalanceLamports()
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
    throw new Error(
      `Gas estimate exceeds max per operation: ${estimatedFee} > ${limits.maxGasPerOpLamports}`,
    )
  }
  if (balanceBefore - estimatedFee < limits.minBalanceLamports) {
    throw new Error('Gas sponsor balance would fall below minimum after this operation')
  }

  const wire = getBase64EncodedWireTransaction(signed)
  await simulateOrThrow(wire)
  const sig = await getSolanaRpc()
    .sendTransaction(wire, { encoding: 'base64', preflightCommitment: 'confirmed' })
    .send()
  await waitForSignatureConfirmation(sig)
  const balanceAfter = await getGasSponsorBalanceLamports()
  const lamportsPaid = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : estimatedFee
  if (lamportsPaid > limits.maxGasPerOpLamports) {
    logger.error(
      { opKind, txSignature: sig, lamportsPaid: lamportsPaid.toString(), max: limits.maxGasPerOpLamports.toString() },
      'gas sponsor operation exceeded configured max after confirmation',
    )
  }
  await recordGasLedger({
    opKind,
    lamportsPaid,
    txSignature: sig,
    ...context,
  })
  return sig
}

function solToLamports(sol: number): bigint {
  return BigInt(Math.ceil(sol * LAMPORTS_PER_SOL))
}

async function getGasSponsorBalanceLamports(): Promise<bigint> {
  const { value } = await getSolanaRpc().getBalance(getGasSponsorAddress(), { commitment: 'confirmed' }).send()
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
      throw new Error(`Solana transaction failed: ${jsonStr(status.err)}`)
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
