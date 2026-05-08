/**
 * Ownership instructions (disc 7..9): transfer / copy / make_public.
 */

import type { Address, Instruction } from '@solana/kit';
import { ByteWriter } from '../lib/serialization.js';
import { DISC } from './discriminators.js';
import { ENCRYPT_PROGRAM_ID } from '../solana/programIds.js';
import { makeInstruction } from '../solana/instructions.js';
import { getAddressCodec } from '@solana/kit';

const addressCodec = getAddressCodec();

export type TransferCiphertextArgs = {
  authority: Address;
  ciphertextAccount: Address;
  newOwner: Address;
};

export function buildTransferCiphertextIx(args: TransferCiphertextArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.TRANSFER_CIPHERTEXT)
    .bytes(new Uint8Array(addressCodec.encode(args.newOwner)))
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.authority, signer: true, writable: false },
      { address: args.ciphertextAccount, writable: true },
    ],
    data
  );
}

export type CopyCiphertextArgs = {
  payer: Address;
  authority: Address;
  source: Address;
  destination: Address;
};

export function buildCopyCiphertextIx(args: CopyCiphertextArgs): Instruction {
  const data = new ByteWriter().u8(DISC.COPY_CIPHERTEXT).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.payer, signer: true, writable: true },
      { address: args.authority, signer: true, writable: false },
      { address: args.source, writable: false },
      { address: args.destination, writable: true },
    ],
    data
  );
}

export type MakePublicArgs = {
  authority: Address;
  ciphertextAccount: Address;
};

export function buildMakePublicIx(args: MakePublicArgs): Instruction {
  const data = new ByteWriter().u8(DISC.MAKE_PUBLIC).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.authority, signer: true, writable: false },
      { address: args.ciphertextAccount, writable: true },
    ],
    data
  );
}
