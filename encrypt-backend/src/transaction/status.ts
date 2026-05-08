/**
 * Solana transaction status helpers.
 */

import { rpc } from '../solana/connection.js';
import { Errors } from '../lib/errors.js';
import type { Signature } from '@solana/kit';

export type TxStatus = {
  signature: string;
  status: 'unknown' | 'processed' | 'confirmed' | 'finalized' | 'failed';
  slot: number | null;
  err: unknown | null;
  confirmations: number | null;
};

export async function getTransactionStatus(signature: string): Promise<TxStatus> {
  try {
    const res = await rpc.getSignatureStatuses([signature as Signature]).send();
    const value = res.value[0];
    if (!value) {
      return { signature, status: 'unknown', slot: null, err: null, confirmations: null };
    }
    let status: TxStatus['status'] = 'processed';
    if (value.err) status = 'failed';
    else if (value.confirmationStatus === 'finalized') status = 'finalized';
    else if (value.confirmationStatus === 'confirmed') status = 'confirmed';
    return {
      signature,
      status,
      slot: Number(value.slot),
      err: value.err ?? null,
      confirmations: value.confirmations === null ? null : Number(value.confirmations),
    };
  } catch (err) {
    throw Errors.solanaRpc('failed to fetch signature status', err);
  }
}
