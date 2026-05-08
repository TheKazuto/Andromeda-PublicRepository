/**
 * Build an encrypted transfer between two private balances.
 *
 * Sender (sender_balance, EUint64 ciphertext) and receiver (receiver_balance,
 * EUint64 ciphertext) each hold their own ciphertext accounts. Transferring
 * an encrypted amount requires:
 *
 *   sender_balance' = sub_u64(sender_balance, amount)
 *   receiver_balance' = add_u64(receiver_balance, amount)
 *
 * Both reductions run as a single graph executed via execute_graph (disc 4)
 * or two sequential graphs depending on which is registered. The graph
 * bytecode for "transfer_u64" is expected in the operation registry.
 *
 * Returns the unsigned tx for the caller to sign.
 */

import type { Address } from '@solana/kit';
import { createInputCiphertexts } from '../encrypt/createInput.js';
import {
  buildExecuteGraphIx,
  buildCreateInputCiphertextIx,
} from '../graph/builder.js';
import { buildUnsignedTransaction, prefetchBlockhash } from '../solana/instructions.js';
import { FheType } from '../dsl/types.js';
import { getOperation } from '../dsl/operations.js';
import { Errors } from '../lib/errors.js';
import { decodeBase64, encodeBase64 } from '../lib/validation.js';
import { u64ToLeBytes } from '../lib/timeout.js';
import { address as toAddress } from '@solana/kit';

export type TransferArgs = {
  payer: Address;
  sender: Address;
  authorityPda: Address;
  networkEncryptionKey: Address;
  configAccount: Address;
  depositAccount: Address;
  senderBalanceCiphertext: string;   // base58 PDA
  receiverBalanceCiphertext: string; // base58 PDA
  amountPlaintext: bigint;           // off-chain transient — encrypted before send
  amountCiphertextAccount: string;   // explicit account for encrypted amount
  newSenderBalanceOutput: string;    // base58 PDA prepared by caller
  newReceiverBalanceOutput: string;  // base58 PDA prepared by caller
  graphName?: string;                // default "transfer_u64"
};

export type TransferResult = {
  amountCiphertext: string;          // base64 identifier
  amountAccount: string;             // base58 PDA
  unsignedTx: {
    base64: string;
    feePayer: string;
    recentBlockhash: string;
    lastValidBlockHeight: string;
  };
};

export async function buildEncryptedTransfer(args: TransferArgs): Promise<TransferResult> {
  const op = getOperation(args.graphName ?? 'transfer_u64');
  if (!op || op.graphBytes.length === 0) {
    throw Errors.graph(
      `Graph "${args.graphName ?? 'transfer_u64'}" is not registered. Operator must upload graph bytes via /v1/graph/register-bytes.`
    );
  }

  const blockhashPromise = prefetchBlockhash();

  // 1. Encrypt the transfer amount as an EUint64 ciphertext input.
  const amountBytes = u64ToLeBytes(args.amountPlaintext);

  const created = await createInputCiphertexts({
    inputs: [{ ciphertextBytes: amountBytes, fheType: FheType.EUint64 }],
    authorizedAddress: args.sender,
  });

  const amountIdentifier = decodeBase64(created.identifiers[0]!);
  const amountAccount = toAddress(args.amountCiphertextAccount);

  // 2. Register the amount ciphertext on-chain.
  const createAmountIx = buildCreateInputCiphertextIx({
    payer: args.payer,
    authorityPda: args.authorityPda,
    signer: args.sender,
    creator: args.sender,
    networkEncryptionKey: args.networkEncryptionKey,
    ciphertextAccount: amountAccount,
    ciphertextDigest: amountIdentifier,
    fheType: FheType.EUint64,
  });

  // 3. Execute the transfer graph: inputs = [sender_balance, receiver_balance, amount]
  const executeIx = buildExecuteGraphIx({
    payer: args.payer,
    configAccount: args.configAccount,
    depositAccount: args.depositAccount,
    caller: args.sender,
    networkEncryptionKey: args.networkEncryptionKey,
    graphBytes: op.graphBytes,
    inputCiphertexts: [
      toAddress(args.senderBalanceCiphertext),
      toAddress(args.receiverBalanceCiphertext),
      amountAccount,
    ],
    outputCiphertexts: [
      toAddress(args.newSenderBalanceOutput),
      toAddress(args.newReceiverBalanceOutput),
    ],
  });

  await blockhashPromise;

  // 4. Compose unsigned transaction.
  const unsignedTx = await buildUnsignedTransaction({
    feePayer: args.payer,
    instructions: [createAmountIx, executeIx],
    computeUnitLimit: 1_400_000,
  });

  return {
    amountCiphertext: encodeBase64(amountIdentifier),
    amountAccount: args.amountCiphertextAccount,
    unsignedTx: {
      base64: unsignedTx.base64,
      feePayer: unsignedTx.feePayer as unknown as string,
      recentBlockhash: unsignedTx.recentBlockhash,
      lastValidBlockHeight: unsignedTx.lastValidBlockHeight.toString(),
    },
  };
}
