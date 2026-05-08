/**
 * Deposit / withdraw against a private encrypted balance.
 *
 * Both flows reuse the add/sub graphs from the operation registry
 * ("add_u64", "sub_u64"). Deposit increases the balance, withdraw decreases it.
 *
 * For pre-alpha simplicity the amount is encrypted at request time and
 * registered on-chain just before the graph runs. Production flows should
 * separate ciphertext upload from execution to avoid replay races.
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

export type DepositOrWithdrawArgs = {
  payer: Address;
  owner: Address;
  balanceCiphertext: string;        // current balance PDA (base58)
  newBalanceOutput: string;         // pre-allocated PDA for the new balance (base58)
  amountCiphertextAccount: string;  // explicit account for encrypted amount
  authorityPda: Address;
  networkEncryptionKey: Address;
  configAccount: Address;
  depositAccount: Address;
  amountPlaintext: bigint;
};

export type DepositOrWithdrawResult = {
  amountCiphertext: string;
  amountAccount: string;
  unsignedTx: {
    base64: string;
    feePayer: string;
    recentBlockhash: string;
    lastValidBlockHeight: string;
  };
};

async function buildOp(
  args: DepositOrWithdrawArgs,
  graphName: 'add_u64' | 'sub_u64'
): Promise<DepositOrWithdrawResult> {
  const op = getOperation(graphName);
  if (!op || op.graphBytes.length === 0) {
    throw Errors.graph(
      `Graph "${graphName}" is not registered. Upload graph bytes via /v1/graph/register-bytes.`
    );
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
    outputCiphertexts: [toAddress(args.newBalanceOutput)],
  });

  await blockhashPromise;
  const unsignedTx = await buildUnsignedTransaction({
    feePayer: args.payer,
    instructions: [createAmountIx, executeIx],
    computeUnitLimit: 1_000_000,
  });

  return {
    amountCiphertext: encodeBase64(identifier),
    amountAccount: args.amountCiphertextAccount,
    unsignedTx: {
      base64: unsignedTx.base64,
      feePayer: unsignedTx.feePayer as unknown as string,
      recentBlockhash: unsignedTx.recentBlockhash,
      lastValidBlockHeight: unsignedTx.lastValidBlockHeight.toString(),
    },
  };
}

export const buildDeposit = (args: DepositOrWithdrawArgs) => buildOp(args, 'add_u64');
export const buildWithdraw = (args: DepositOrWithdrawArgs) => buildOp(args, 'sub_u64');
