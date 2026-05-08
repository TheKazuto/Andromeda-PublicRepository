/**
 * Build a request_decryption (disc 10) transaction for a ciphertext account.
 */

import type { Address } from '@solana/kit';
import { buildRequestDecryptionIx } from '../graph/gateway.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { encodeBase64 } from '../lib/validation.js';
import { randomBytes } from 'node:crypto';

export type RequestDecryptionArgs = {
  payer: Address;
  requester: Address;
  ciphertextAccount: Address;
  decryptionRequestAccount: Address;
  /** Optional caller-provided 32-byte request id. Random by default. */
  requestId?: Uint8Array;
};

export type RequestDecryptionResult = {
  requestId: string;       // base64
  decryptionRequestAccount: string;
  unsignedTx: {
    base64: string;
    feePayer: string;
    recentBlockhash: string;
    lastValidBlockHeight: string;
  };
};

export async function buildRequestDecryption(args: RequestDecryptionArgs): Promise<RequestDecryptionResult> {
  const id = args.requestId ?? new Uint8Array(randomBytes(32));
  if (id.length !== 32) throw new Error('requestId must be 32 bytes');

  const ix = buildRequestDecryptionIx({
    payer: args.payer,
    requester: args.requester,
    ciphertextAccount: args.ciphertextAccount,
    decryptionRequestAccount: args.decryptionRequestAccount,
    requestId: id,
  });

  const unsignedTx = await buildUnsignedTransaction({
    feePayer: args.payer,
    instructions: [ix],
    computeUnitLimit: 200_000,
  });

  return {
    requestId: encodeBase64(id),
    decryptionRequestAccount: args.decryptionRequestAccount as unknown as string,
    unsignedTx: {
      base64: unsignedTx.base64,
      feePayer: unsignedTx.feePayer as unknown as string,
      recentBlockhash: unsignedTx.recentBlockhash,
      lastValidBlockHeight: unsignedTx.lastValidBlockHeight.toString(),
    },
  };
}
