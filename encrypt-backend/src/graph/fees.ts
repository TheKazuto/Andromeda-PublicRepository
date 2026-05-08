/**
 * Fee instructions (disc 13..18).
 *
 * The fee model accepts ENC and SOL deposits managed by the Encrypt program.
 * See "Fee model" chapter of the developer guide for full payload layouts.
 */

import type { Address, Instruction } from '@solana/kit';
import { ByteWriter } from '../lib/serialization.js';
import { DISC } from './discriminators.js';
import { ENCRYPT_PROGRAM_ID, SYSTEM_PROGRAM_ID } from '../solana/programIds.js';
import { makeInstruction } from '../solana/instructions.js';

export type CreateDepositArgs = {
  payer: Address;
  owner: Address;
  depositPda: Address;
  initialLamports?: bigint;
};

export function buildCreateDepositIx(args: CreateDepositArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.CREATE_DEPOSIT)
    .u64LE(args.initialLamports ?? 0n)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.payer, signer: true, writable: true },
      { address: args.owner, signer: true, writable: false },
      { address: args.depositPda, writable: true },
      { address: SYSTEM_PROGRAM_ID },
    ],
    data
  );
}

export type TopUpArgs = {
  payer: Address;
  depositPda: Address;
  lamports: bigint;
};

export function buildTopUpIx(args: TopUpArgs): Instruction {
  const data = new ByteWriter().u8(DISC.TOP_UP).u64LE(args.lamports).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.payer, signer: true, writable: true },
      { address: args.depositPda, writable: true },
      { address: SYSTEM_PROGRAM_ID },
    ],
    data
  );
}

export type WithdrawArgs = {
  owner: Address;
  depositPda: Address;
  destination: Address;
  lamports: bigint;
};

export function buildWithdrawIx(args: WithdrawArgs): Instruction {
  const data = new ByteWriter().u8(DISC.WITHDRAW).u64LE(args.lamports).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.owner, signer: true, writable: false },
      { address: args.depositPda, writable: true },
      { address: args.destination, writable: true },
    ],
    data
  );
}

export type RequestWithdrawArgs = {
  owner: Address;
  depositPda: Address;
  lamports: bigint;
};

export function buildRequestWithdrawIx(args: RequestWithdrawArgs): Instruction {
  const data = new ByteWriter().u8(DISC.REQUEST_WITHDRAW).u64LE(args.lamports).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.owner, signer: true, writable: false },
      { address: args.depositPda, writable: true },
    ],
    data
  );
}

export type ReimburseArgs = {
  authority: Address;
  depositPda: Address;
  lamports: bigint;
};

export function buildReimburseIx(args: ReimburseArgs): Instruction {
  const data = new ByteWriter().u8(DISC.REIMBURSE).u64LE(args.lamports).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.authority, signer: true, writable: false },
      { address: args.depositPda, writable: true },
    ],
    data
  );
}

export type UpdateConfigFeesArgs = {
  authority: Address;
  configAccount: Address;
  configBytes: Uint8Array;
};

export function buildUpdateConfigFeesIx(args: UpdateConfigFeesArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.UPDATE_CONFIG_FEES)
    .vec(args.configBytes)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.authority, signer: true, writable: false },
      { address: args.configAccount, writable: true },
    ],
    data
  );
}
