/**
 * Encrypted balance check: produces a cipher boolean indicating whether
 * `balance >= amount` without revealing either value.
 *
 * Uses the "cmp_gt_u64" or "cmp_eq_u64" graph from the operation registry.
 * The result is a fresh EBool ciphertext owned by the caller; downstream
 * code can request a decrypt via the gateway flow if it needs the bit
 * cleartext.
 */

import type { Address } from '@solana/kit';
import { address as toAddress } from '@solana/kit';
import { createInputCiphertexts } from '../encrypt/createInput.js';
import {
  buildCreateInputCiphertextIx,
  buildExecuteGraphIx,
} from '../graph/builder.js';
import { buildUnsignedTransaction, prefetchBlockhash } from '../solana/instructions.js';
import { FheType } from '../dsl/types.js';
import { getOperation } from '../dsl/operations.js';
import { Errors } from '../lib/errors.js';
import { decodeBase64, encodeBase64 } from '../lib/validation.js';
import { u64ToLeBytes } from '../lib/timeout.js';

export type BalanceCheckArgs = {
  payer: Address;
  owner: Address;
  authorityPda: Address;
  networkEncryptionKey: Address;
  configAccount: Address;
  depositAccount: Address;
  balanceCiphertext: string;          // base58 PDA
  amountPlaintext: bigint;
  amountCiphertextAccount: string;    // explicit account for encrypted amount
  resultOutput: string;               // base58 PDA for EBool result
  /** Default "cmp_gt_u64" — also accepts "cmp_lt_u64", "cmp_eq_u64". */
  graphName?: 'cmp_gt_u64' | 'cmp_lt_u64' | 'cmp_eq_u64';
};

export type BalanceCheckResult = {
  resultCiphertextAccount: string;
  amountCiphertext: string;
  unsignedTx: {
    base64: string;
    feePayer: string;
    recentBlockhash: string;
    lastValidBlockHeight: string;
  };
};

export async function buildBalanceCheck(args: BalanceCheckArgs): Promise<BalanceCheckResult> {
  const name = args.graphName ?? 'cmp_gt_u64';
  const op = getOperation(name);
  if (!op || op.graphBytes.length === 0) {
    throw Errors.graph(`Graph "${name}" is not registered.`);
  }

  const blockhashPromise = prefetchBlockhash();
  const amountBytes = u64ToLeBytes(args.amountPlaintext);

  const created = await createInputCiphertexts({
    inputs: [{ ciphertextBytes: amountBytes, fheType: FheType.EUint64 }],
    authorizedAddress: args.owner,
  });

  const identifier = decodeBase64(created.identifiers[0]!);
  const amountAccount = toAddress(args.amountCiphertextAccount);

  const createAmountIx = buildCreateInputCiphertextIx({
    payer: args.payer,
    authorityPda: args.authorityPda,
    signer: args.owner,
    creator: args.owner,
    networkEncryptionKey: args.networkEncryptionKey,
    ciphertextAccount: amountAccount,
    ciphertextDigest: identifier,
    fheType: FheType.EUint64,
  });

  const executeIx = buildExecuteGraphIx({
    payer: args.payer,
    configAccount: args.configAccount,
    depositAccount: args.depositAccount,
    caller: args.owner,
    networkEncryptionKey: args.networkEncryptionKey,
    graphBytes: op.graphBytes,
    inputCiphertexts: [toAddress(args.balanceCiphertext), amountAccount],
    outputCiphertexts: [toAddress(args.resultOutput)],
  });

  await blockhashPromise;

  const unsignedTx = await buildUnsignedTransaction({
    feePayer: args.payer,
    instructions: [createAmountIx, executeIx],
    computeUnitLimit: 1_000_000,
  });

  return {
    resultCiphertextAccount: args.resultOutput,
    amountCiphertext: encodeBase64(identifier),
    unsignedTx: {
      base64: unsignedTx.base64,
      feePayer: unsignedTx.feePayer as unknown as string,
      recentBlockhash: unsignedTx.recentBlockhash,
      lastValidBlockHeight: unsignedTx.lastValidBlockHeight.toString(),
    },
  };
}
