/**
 * Single instrumentation + circuit-breaker wrapper for every Solana RPC
 * call from encrypt-backend. Mirrors ika-backend/src/engine/solana-rpc.ts.
 *
 * Behaviour:
 *   - When the breaker is open, throw CircuitOpenError immediately so the
 *     handler can map to 503 with Retry-After.
 *   - On success, reset the breaker for this op.
 *   - On failure, record outcome and feed the breaker — except for
 *     `blockhash_expired`, which is normal under load and would
 *     otherwise flap the breaker on every cache miss.
 */

import { logger } from '../lib/logger.js';
import {
  classifySolanaRpcError,
  solanaRpcBreakerState,
  solanaRpcBreakerTripsTotal,
  solanaRpcDuration,
  solanaRpcTotal,
} from '../lib/metrics.js';
import {
  CircuitOpenError,
  getState,
  preCall,
  recordFailure,
  recordSuccess,
} from '../lib/breaker.js';

export { CircuitOpenError, isCircuitOpen } from '../lib/breaker.js';

export async function withSolanaRpc<T>(op: string, fn: () => Promise<T>): Promise<T> {
  const key = `solana_rpc:${op}`;
  try {
    preCall(key);
  } catch (err) {
    if (err instanceof CircuitOpenError) {
      solanaRpcBreakerState.labels(op).set(getState(key) === 'open' ? 1 : 2);
      solanaRpcTotal.labels(op, 'circuit_open').inc();
    }
    throw err;
  }
  const stateBefore = getState(key);
  const started = process.hrtime.bigint();
  let outcome = 'ok';
  try {
    const result = await fn();
    recordSuccess(key);
    solanaRpcBreakerState.labels(op).set(0);
    return result;
  } catch (err) {
    outcome = classifySolanaRpcError(err);
    if (outcome !== 'blockhash_expired') {
      recordFailure(key);
      const stateAfter = getState(key);
      solanaRpcBreakerState
        .labels(op)
        .set(stateAfter === 'open' ? 1 : stateAfter === 'half-open' ? 2 : 0);
      if (stateBefore !== 'open' && stateAfter === 'open') {
        solanaRpcBreakerTripsTotal.labels(op).inc();
        logger.warn({ op }, 'Solana RPC circuit breaker tripped open');
      }
    }
    throw err;
  } finally {
    const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
    solanaRpcDuration.labels(op, outcome).observe(elapsed);
    solanaRpcTotal.labels(op, outcome).inc();
  }
}
