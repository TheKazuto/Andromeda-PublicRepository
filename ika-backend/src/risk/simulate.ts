/**
 * Transaction simulation per chain family.
 *
 * Solana: real simulation via the `simulateTransaction` RPC (revert check,
 *         compute units, decoded instructions).
 * EVM/Tron: real simulation via `eth_call` (revert check) + `eth_estimateGas`
 *           (gas), with structured effects (native/token transfers, approvals,
 *           contract call) decoded from the calldata. When no RPC is configured
 *           for the chain it degrades honestly to static calldata analysis
 *           (verified=false). State-diff traces are out of scope.
 * Other chains: no decoder/simulation; returned as not-verified (never "safe").
 *
 * Principles:
 * - Recompute the digest and verify it matches expectedDigestHex before simulating.
 * - If the digest doesn't match, return early (attack vector prevention).
 * - If the RPC call fails, mark effectsExtracted=false with a warning.
 * - Never fabricate effects; always be honest about what was (or wasn't) extracted.
 */

import { Connection } from '@solana/web3.js'
import { BaseError, ExecutionRevertedError } from 'viem'
import type {
  TransactionSimulation,
  SolanaInstructionDecoded,
  CalldataRisk,
} from './types.js'
import { preProcessForChain } from '../chain/preprocess.js'
import { schemeDigest } from '../chain/digest.js'
import { resolveChainParams } from '../chain/chains.js'
import { decodeSolanaTransaction, decodeForChain, decodeEvmTransaction, extractEvmEffects } from './decode.js'
import { checkRpcUrl } from './ssrf.js'
import { deriveAddress } from '../chain/address.js'
import { logger } from '../logger.js'

export interface SimulateRequest {
  chainId: string
  payloadHex: string
  kind: 'transaction' | 'message'
  expectedDigestHex: string
  dwalletPublicKeyHex?: string | undefined
}

/**
 * Simulate a transaction on its destination chain.
 */
export async function simulateTransaction(
  req: SimulateRequest,
  clientRpcUrl?: string,
): Promise<TransactionSimulation> {
  try {
    const params = resolveChainParams(req.chainId)

    // Recompute the digest and verify it matches
    const payload = Buffer.from(req.payloadHex.startsWith('0x') ? req.payloadHex.slice(2) : req.payloadHex, 'hex')
    const preprocessed = preProcessForChain(req.chainId, new Uint8Array(payload), req.kind)
    const computedDigest = schemeDigest(params.scheme, preprocessed)

    if (!computedDigest) {
      return {
        ok: false,
        digestMatches: false,
        actualDigestHex: undefined,
        destination: undefined,
        verified: false,
        assetChanges: [],
        approvals: [],
        calls: [],
        effectsExtracted: false,
        willRevert: false,
        warnings: ['Digest algorithm not supported for this scheme'],
      }
    }

    const computedDigestHex = Buffer.from(computedDigest).toString('hex')
    const digestMatches = computedDigestHex === req.expectedDigestHex.toLowerCase()

    if (!digestMatches) {
      return {
        ok: false,
        digestMatches: false,
        actualDigestHex: computedDigestHex,
        destination: undefined,
        verified: false,
        assetChanges: [],
        approvals: [],
        calls: [],
        effectsExtracted: false,
        willRevert: false,
        warnings: ['Transaction digest mismatch — different transaction will be signed'],
      }
    }

    // Decode calldata for risk analysis first (works for all chains via decodeForChain)
    const calldataRisk = decodeForChain(req.chainId, req.payloadHex, req.kind)

    // The simulation RPC is provided by the client (we don't host RPCs). Validate
    // it against SSRF before any outbound call; if unsafe, drop it and degrade.
    let safeRpc: string | undefined
    let rpcRejected = false
    if (clientRpcUrl) {
      const check = await checkRpcUrl(clientRpcUrl)
      if (check.ok) {
        safeRpc = clientRpcUrl
      } else {
        rpcRejected = true
        logger.warn({ scope: 'simulateTransaction', reason: check.reason }, 'client RPC URL rejected (SSRF guard)')
      }
    }

    // Simulate based on chain family
    switch (params.chainFamily) {
      case 'Solana': {
        // The simulation RPC must be the client's. Our paid core Solana RPC is
        // reserved for internal use (submitting to Ika + our programs) and must
        // NOT be used to simulate user destination txs. Without a client RPC we
        // decode-only (no RPC call).
        if (!safeRpc) {
          const decoded = decodeSolanaTransaction(req.payloadHex)
          return {
            ok: true,
            digestMatches: true,
            actualDigestHex: computedDigestHex,
            destination: undefined,
            verified: false,
            assetChanges: [],
            approvals: [],
            calls: [],
            effectsExtracted: false,
            calldataRisk,
            solanaInstructions: decoded.error ? [] : decoded.instructions,
            willRevert: false,
            warnings: [
              rpcRejected
                ? 'Provided RPC URL rejected (unsafe target); static instruction decode only'
                : 'No RPC URL provided; static instruction decode only',
            ],
          }
        }
        return await simulateSolana(req, safeRpc, payload, computedDigest, computedDigestHex, calldataRisk)
      }

      case 'EVM':
      case 'Tron': {
        if (!safeRpc) {
          // No usable RPC: degrade honestly to static calldata effects.
          const txView = decodeEvmTransaction(req.payloadHex)
          const staticEffects =
            req.kind === 'transaction'
              ? extractEvmEffects(txView)
              : { assetChanges: [], approvals: [], calls: [] }
          return {
            ok: true,
            digestMatches: true,
            actualDigestHex: computedDigestHex,
            destination: txView.to,
            verified: false,
            assetChanges: staticEffects.assetChanges,
            approvals: staticEffects.approvals,
            calls: staticEffects.calls,
            effectsExtracted: false,
            calldataRisk,
            willRevert: false,
            warnings: [
              rpcRejected
                ? 'Provided RPC URL rejected (unsafe target); static calldata analysis only'
                : 'No RPC URL provided; static calldata analysis only',
            ],
          }
        }
        return await simulateEvm(req, safeRpc, computedDigestHex, calldataRisk)
      }

      case 'Cosmos':
      case 'Bitcoin':
      case 'Filecoin':
      case 'Stellar':
      case 'Algorand':
      case 'Aptos':
      case 'MultiversX':
      case 'TON':
      case 'Casper':
      case 'Tezos':
      case 'IOTA':
      case 'NEAR':
      case 'Substrate':
      case 'VeChain':
      case 'Avalanche':
        return {
          ok: false,
          digestMatches: true,
          actualDigestHex: computedDigestHex,
          destination: undefined,
          verified: false,
          assetChanges: [],
          approvals: [],
          calls: [],
          effectsExtracted: false,
          calldataRisk,
          willRevert: false,
          warnings: [`Simulation not available for ${params.chainFamily}; decoder not implemented`],
        }

      default:
        return {
          ok: false,
          digestMatches: true,
          actualDigestHex: computedDigestHex,
          destination: undefined,
          verified: false,
          assetChanges: [],
          approvals: [],
          calls: [],
          effectsExtracted: false,
          willRevert: false,
          warnings: ['Unsupported chain'],
        }
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : 'unknown'
    logger.warn({ scope: 'simulateTransaction', errorMessage: errMsg }, 'Simulation failed')
    return {
      ok: false,
      digestMatches: false,
      actualDigestHex: undefined,
      destination: undefined,
      verified: false,
      assetChanges: [],
      approvals: [],
      calls: [],
      effectsExtracted: false,
      willRevert: false,
      warnings: ['Simulation failed; unable to verify transaction'],
    }
  }
}

/**
 * Simulate a Solana transaction.
 */
async function simulateSolana(
  req: SimulateRequest,
  rpcUrl: string,
  payload: Buffer,
  digest: Uint8Array,
  digestHex: string,
  calldataRisk: CalldataRisk,
): Promise<TransactionSimulation> {
  try {
    const { VersionedTransaction } = await import('@solana/web3.js')

    const tx = VersionedTransaction.deserialize(new Uint8Array(payload))
    const connection = new Connection(rpcUrl, 'confirmed')

    // Simulate the transaction
    const sim = await connection.simulateTransaction(tx, {
      sigVerify: false,
      commitment: 'confirmed',
    })

    const instructions: SolanaInstructionDecoded[] = []
    const warnings: string[] = []

    if (sim.value.err) {
      warnings.push(`Simulation succeeded; transaction would revert: ${sim.value.err}`)
      return {
        ok: false,
        digestMatches: true,
        actualDigestHex: digestHex,
        destination: undefined,
        verified: true,
        assetChanges: [],
        approvals: [],
        calls: [],
        effectsExtracted: false,
        calldataRisk,
        solanaInstructions: instructions,
        willRevert: true,
        warnings,
      }
    }

    // Decode instructions for risk analysis. The SPL approve/authority signals
    // are surfaced via `calldataRisk` (decodeForChain); `solanaInstructions`
    // carries the decoded detail for the client. Structured asset/approval
    // deltas are not extracted from Solana here (no honest source without an
    // account-state diff), so those arrays stay empty.
    const decoded = decodeSolanaTransaction(req.payloadHex)
    if (decoded.error) {
      warnings.push('Instruction decode failed; static analysis only')
    } else {
      instructions.push(...decoded.instructions)
    }

    const logCount = sim.value.logs ? sim.value.logs.length : 0

    return {
      ok: true,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination: undefined,
      verified: true,
      assetChanges: [],
      approvals: [],
      calls: [],
      effectsExtracted: instructions.length > 0 || logCount > 0,
      calldataRisk,
      solanaInstructions: instructions,
      estimatedGas: sim.value.unitsConsumed ? String(sim.value.unitsConsumed) : (undefined as string | undefined),
      willRevert: false,
      warnings,
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : 'unknown'
    logger.warn({ scope: 'simulateSolana', errorMessage: errMsg }, 'Solana simulation failed')
    return {
      ok: false,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination: undefined,
      verified: false,
      assetChanges: [],
      approvals: [],
      calls: [],
      effectsExtracted: false,
      calldataRisk,
      willRevert: false,
      warnings: ['Solana simulation unavailable'],
    }
  }
}

/**
 * Tell a real on-chain revert apart from an RPC/network failure. Only an actual
 * `ExecutionRevertedError` (or a message that says "revert") counts as a revert;
 * everything else is treated as RPC unavailability so we never report a revert
 * we did not actually observe.
 */
function isEvmRevert(err: unknown): boolean {
  // Primary, precise signal: viem wraps an on-chain revert as ExecutionRevertedError.
  if (err instanceof BaseError && err.walk((e) => e instanceof ExecutionRevertedError)) {
    return true
  }
  // Fallback for RPCs whose error viem doesn't classify: require the canonical
  // EVM phrasing, not just any "revert", so network/timeout errors aren't
  // misread as an on-chain revert.
  const msg = err instanceof BaseError ? err.shortMessage : err instanceof Error ? err.message : String(err)
  return /execution reverted|\breverted\b/i.test(msg)
}

/**
 * Simulate an EVM/Tron transaction against its destination-chain RPC.
 *
 * Runs a real `eth_call` (revert detection) and `eth_estimateGas` (gas), and
 * reports the structured effects decoded from the calldata (native/token
 * transfers, approvals, contract call). A true on-chain revert is reported as
 * `willRevert`; an RPC/network failure degrades to static analysis
 * (verified=false) without fabricating a result. State-diff traces are out of
 * scope.
 */
async function simulateEvm(
  req: SimulateRequest,
  evmRpcUrl: string,
  digestHex: string,
  calldataRisk: CalldataRisk,
): Promise<TransactionSimulation> {
  const txView = decodeEvmTransaction(req.payloadHex)
  const destination = txView.to
  const effects = extractEvmEffects(txView)

  // A transaction-prefixed payload that didn't parse is a malformed tx, not
  // plain calldata — degrade honestly instead of running a misleading eth_call
  // against an undefined destination.
  if (req.kind === 'transaction' && !txView.parsed) {
    return {
      ok: false,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination: undefined,
      verified: false,
      assetChanges: [],
      approvals: [],
      calls: [],
      effectsExtracted: false,
      calldataRisk,
      willRevert: false,
      warnings: ['Could not parse EVM transaction; static calldata analysis only'],
    }
  }

  // Messages are signed, not executed — nothing to simulate on-chain.
  if (req.kind === 'message') {
    return {
      ok: true,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination,
      verified: true,
      assetChanges: [],
      approvals: [],
      calls: [],
      effectsExtracted: false,
      calldataRisk,
      willRevert: false,
      warnings: ['EVM message signature; not executed on-chain'],
    }
  }

  // Derive the sender so eth_call/estimateGas run against the real account.
  let account: `0x${string}` | undefined
  if (req.dwalletPublicKeyHex) {
    try {
      const pkHex = req.dwalletPublicKeyHex.startsWith('0x') ? req.dwalletPublicKeyHex.slice(2) : req.dwalletPublicKeyHex
      account = deriveAddress(new Uint8Array(Buffer.from(pkHex, 'hex')), req.chainId) as `0x${string}`
    } catch {
      account = undefined
    }
  }

  try {
    const { createPublicClient, http } = await import('viem')
    // `redirect: 'error'` prevents a validated host from redirecting the call to
    // an internal target after the SSRF check (defense in depth).
    const client = createPublicClient({
      transport: http(evmRpcUrl, { timeout: 8000, retryCount: 0, fetchOptions: { redirect: 'error' } }),
    })

    const to = destination as `0x${string}` | undefined
    const data = txView.data as `0x${string}`
    const value = txView.value

    let willRevert = false
    const warnings: string[] = []

    try {
      await client.call({ account, to, data, value })
    } catch (err) {
      if (isEvmRevert(err)) {
        willRevert = true
        warnings.push('Transaction would revert on-chain (eth_call reverted)')
      } else {
        // RPC/network failure — honest degradation, NOT a revert.
        return {
          ok: false,
          digestMatches: true,
          actualDigestHex: digestHex,
          destination,
          verified: false,
          assetChanges: effects.assetChanges,
          approvals: effects.approvals,
          calls: effects.calls,
          effectsExtracted: false,
          calldataRisk,
          willRevert: false,
          warnings: ['EVM RPC unavailable; static calldata analysis only'],
        }
      }
    }

    let estimatedGas: string | undefined
    if (!willRevert && account) {
      try {
        const gas = await client.estimateGas({ account, to, data, value })
        estimatedGas = gas.toString()
      } catch {
        // estimateGas can fail independently of the call; non-fatal.
      }
    }

    return {
      ok: !willRevert,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination,
      verified: true,
      assetChanges: effects.assetChanges,
      approvals: effects.approvals,
      calls: effects.calls,
      effectsExtracted: true,
      calldataRisk,
      estimatedGas,
      willRevert,
      warnings: warnings.length > 0 ? warnings : ['EVM transaction simulated via eth_call'],
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : 'unknown'
    logger.warn({ scope: 'simulateEvm', errorMessage: errMsg }, 'EVM simulation failed')
    return {
      ok: false,
      digestMatches: true,
      actualDigestHex: digestHex,
      destination,
      verified: false,
      assetChanges: effects.assetChanges,
      approvals: effects.approvals,
      calls: effects.calls,
      effectsExtracted: false,
      calldataRisk,
      willRevert: false,
      warnings: ['EVM simulation failed; static calldata analysis only'],
    }
  }
}
