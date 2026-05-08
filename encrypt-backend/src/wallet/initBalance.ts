/**
 * Initialize a private encrypted balance for a wallet (owner pubkey).
 *
 * Flow:
 *   1. Off-chain caller submits 0u64 plaintext to gRPC CreateInput, receiving
 *      a ciphertext identifier representing "encrypted zero".
 *   2. Caller supplies the ciphertext account address to initialize.
 *   3. We build a `create_input_ciphertext` instruction (disc 1) with the
 *      caller as authority + payer.
 *   4. The unsigned transaction is returned to the caller for signing.
 *
 * The owner can later use `transfer`, `deposit`, `withdraw` operations.
 */

import type { Address } from '@solana/kit';
import { createInputCiphertexts } from '../encrypt/createInput.js';
import { buildCreateInputCiphertextIx } from '../graph/builder.js';
import { buildUnsignedTransaction, prefetchBlockhash } from '../solana/instructions.js';
import { FheType } from '../dsl/types.js';
import { encodeBase64, decodeBase64 } from '../lib/validation.js';

export type InitBalanceArgs = {
  payer: Address;
  owner: Address;
  ciphertextAccount: Address;
  authorityPda: Address;
  networkEncryptionKey: Address;
};

export type InitBalanceResult = {
  ciphertextIdentifier: string; // base64
  ciphertextAccount: string;    // base58 PDA
  unsignedTx: {
    base64: string;
    feePayer: string;
    recentBlockhash: string;
    lastValidBlockHeight: string;
  };
};

const ZERO_U64 = new Uint8Array(8); // little-endian zero

export async function initEncryptedBalance(args: InitBalanceArgs): Promise<InitBalanceResult> {
  const blockhashPromise = prefetchBlockhash();
  // Step 1: ask Encrypt executor to wrap a zero plaintext as an EUint64 input.
  const created = await createInputCiphertexts({
    inputs: [{ ciphertextBytes: ZERO_U64, fheType: FheType.EUint64 }],
    authorizedAddress: args.owner,
  });

  const identifierBase64 = created.identifiers[0]!;
  const identifierBytes = decodeBase64(identifierBase64);

  const ix = buildCreateInputCiphertextIx({
    payer: args.payer,
    authorityPda: args.authorityPda,
    signer: args.owner,
    creator: args.owner,
    networkEncryptionKey: args.networkEncryptionKey,
    ciphertextAccount: args.ciphertextAccount,
    ciphertextDigest: identifierBytes,
    fheType: FheType.EUint64,
  });

  await blockhashPromise;
  // Step 4: wrap into unsigned tx
  const unsignedTx = await buildUnsignedTransaction({
    feePayer: args.payer,
    instructions: [ix],
    computeUnitLimit: 400_000,
  });

  return {
    ciphertextIdentifier: identifierBase64,
    ciphertextAccount: args.ciphertextAccount as unknown as string,
    unsignedTx: {
      base64: unsignedTx.base64,
      feePayer: unsignedTx.feePayer as unknown as string,
      recentBlockhash: unsignedTx.recentBlockhash,
      lastValidBlockHeight: unsignedTx.lastValidBlockHeight.toString(),
    },
  };
}

export { encodeBase64 };
