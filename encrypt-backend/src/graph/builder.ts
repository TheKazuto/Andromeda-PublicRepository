/**
 * Builds Encrypt program instructions for the Executor group:
 *   - create_input_ciphertext   (disc 1)
 *   - create_plaintext_ciphertext (disc 2)
 *   - commit_ciphertext          (disc 3)
 *   - execute_graph              (disc 4)
 *   - register_graph             (disc 5)
 *   - execute_registered_graph   (disc 6)
 *
 * IMPORTANT — pre-alpha caveat:
 * The exact account ordering and arg layout for each instruction is
 * defined in `encrypt-pre-alpha/chains/solana/program/src/instruction.rs`
 * and may shift across releases. The functions below produce the expected
 * shape based on the latest documented layout. When running against a new
 * release, verify with `chains/solana/examples/*` in the upstream repo.
 */

import type { Address, Instruction } from '@solana/kit';
import { ByteWriter } from '../lib/serialization.js';
import { DISC } from './discriminators.js';
import { ENCRYPT_PROGRAM_ID, SYSTEM_PROGRAM_ID } from '../solana/programIds.js';
import { makeInstruction, type AccountInput } from '../solana/instructions.js';

// -----------------------------------------------------------------------------
// create_input_ciphertext (disc 1)
// -----------------------------------------------------------------------------

export type CreateInputCiphertextArgs = {
  payer: Address;
  authorityPda: Address;
  signer: Address;
  creator: Address;
  networkEncryptionKey: Address;
  ciphertextAccount: Address;
  ciphertextDigest: Uint8Array;
  fheType: number;
};

export function buildCreateInputCiphertextIx(args: CreateInputCiphertextArgs): Instruction {
  if (args.ciphertextDigest.length !== 32) {
    throw new Error('ciphertextDigest must be 32 bytes');
  }
  const data = new ByteWriter()
    .u8(DISC.CREATE_INPUT_CIPHERTEXT)
    .u8(args.fheType)
    .bytes(args.ciphertextDigest)
    .build();

  const accounts: AccountInput[] = [
    { address: args.authorityPda, writable: false },
    { address: args.signer, signer: true, writable: false },
    { address: args.ciphertextAccount, writable: true },
    { address: args.creator, writable: false },
    { address: args.networkEncryptionKey, writable: false },
    { address: args.payer, signer: true, writable: true },
    { address: SYSTEM_PROGRAM_ID },
  ];
  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}

// -----------------------------------------------------------------------------
// create_plaintext_ciphertext (disc 2)
// -----------------------------------------------------------------------------

export type CreatePlaintextCiphertextArgs = {
  payer: Address;
  configAccount: Address;
  depositAccount: Address;
  creator: Address;
  networkEncryptionKey: Address;
  ciphertextAccount: Address;
  fheType: number;
};

export function buildCreatePlaintextCiphertextIx(args: CreatePlaintextCiphertextArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.CREATE_PLAINTEXT_CIPHERTEXT)
    .u8(args.fheType)
    .build();

  const accounts: AccountInput[] = [
    { address: args.configAccount, writable: false },
    { address: args.depositAccount, writable: true },
    { address: args.ciphertextAccount, writable: true },
    { address: args.creator, writable: false },
    { address: args.networkEncryptionKey, writable: false },
    { address: args.payer, signer: true, writable: true },
    { address: SYSTEM_PROGRAM_ID },
  ];

  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}

// -----------------------------------------------------------------------------
// commit_ciphertext (disc 3)
// -----------------------------------------------------------------------------

export type CommitCiphertextArgs = {
  authorityPda: Address;
  signer: Address;
  ciphertextAccount: Address;
  digest: Uint8Array;               // 32 bytes
};

export function buildCommitCiphertextIx(args: CommitCiphertextArgs): Instruction {
  if (args.digest.length !== 32) {
    throw new Error('digest must be 32 bytes');
  }
  const data = new ByteWriter()
    .u8(DISC.COMMIT_CIPHERTEXT)
    .bytes(args.digest)
    .build();
  const accounts: AccountInput[] = [
    { address: args.authorityPda, writable: false },
    { address: args.signer, signer: true, writable: false },
    { address: args.ciphertextAccount, writable: true },
  ];
  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}

// -----------------------------------------------------------------------------
// execute_graph (disc 4)
// -----------------------------------------------------------------------------

export type ExecuteGraphArgs = {
  payer: Address;
  configAccount: Address;
  depositAccount: Address;
  caller: Address;
  networkEncryptionKey: Address;
  /** Compiled graph bytes from `#[encrypt_fn_graph]` or `register_graph` flow. */
  graphBytes: Uint8Array;
  /** Inputs to the graph — addresses of existing ciphertext accounts. */
  inputCiphertexts: Address[];
  /** Output ciphertext accounts (PDAs allocated for the results). */
  outputCiphertexts: Address[];
};

export function buildExecuteGraphIx(args: ExecuteGraphArgs): Instruction {
  const writer = new ByteWriter()
    .u8(DISC.EXECUTE_GRAPH)
    .u16LE(args.graphBytes.length)
    .bytes(args.graphBytes);

  const data = writer.build();

  const accounts: AccountInput[] = [
    { address: args.configAccount, writable: false },
    { address: args.depositAccount, writable: true },
    { address: args.caller, writable: false },
    { address: args.networkEncryptionKey, writable: false },
    { address: args.payer, signer: true, writable: true },
  ];
  for (const ct of args.inputCiphertexts) accounts.push({ address: ct, writable: false });
  for (const ct of args.outputCiphertexts) accounts.push({ address: ct, writable: true });

  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}

// -----------------------------------------------------------------------------
// register_graph (disc 5)
// -----------------------------------------------------------------------------

export type RegisterGraphArgs = {
  payer: Address;
  registrar: Address;
  graphAccount: Address;
  bump: number;
  graphHash: Uint8Array;
  graphBytes: Uint8Array;
};

export function buildRegisterGraphIx(args: RegisterGraphArgs): Instruction {
  if (args.graphHash.length !== 32) throw new Error('graphHash must be 32 bytes');
  const data = new ByteWriter()
    .u8(DISC.REGISTER_GRAPH)
    .u8(args.bump)
    .bytes(args.graphHash)
    .u16LE(args.graphBytes.length)
    .bytes(args.graphBytes)
    .build();

  const accounts: AccountInput[] = [
    { address: args.graphAccount, writable: true },
    { address: args.registrar, signer: true, writable: false },
    { address: args.payer, signer: true, writable: true },
    { address: SYSTEM_PROGRAM_ID },
  ];
  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}

// -----------------------------------------------------------------------------
// execute_registered_graph (disc 6)
// -----------------------------------------------------------------------------

export type ExecuteRegisteredGraphArgs = {
  payer: Address;
  configAccount: Address;
  depositAccount: Address;
  caller: Address;
  networkEncryptionKey: Address;
  graphAccount: Address;
  inputCiphertexts: Address[];
  outputCiphertexts: Address[];
};

export function buildExecuteRegisteredGraphIx(args: ExecuteRegisteredGraphArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.EXECUTE_REGISTERED_GRAPH)
    .u16LE(args.inputCiphertexts.length)
    .build();

  const accounts: AccountInput[] = [
    { address: args.configAccount, writable: false },
    { address: args.depositAccount, writable: true },
    { address: args.graphAccount, writable: false },
    { address: args.caller, writable: false },
    { address: args.networkEncryptionKey, writable: false },
    { address: args.payer, signer: true, writable: true },
  ];
  for (const ct of args.inputCiphertexts) accounts.push({ address: ct, writable: false });
  for (const ct of args.outputCiphertexts) accounts.push({ address: ct, writable: true });

  return makeInstruction(ENCRYPT_PROGRAM_ID, accounts, data);
}
