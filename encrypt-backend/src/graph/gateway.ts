/**
 * Gateway / decryption instructions (disc 10..12).
 */

import type { Address, Instruction } from '@solana/kit';
import { ByteWriter } from '../lib/serialization.js';
import { DISC } from './discriminators.js';
import { ENCRYPT_PROGRAM_ID, SYSTEM_PROGRAM_ID } from '../solana/programIds.js';
import { makeInstruction } from '../solana/instructions.js';

export type RequestDecryptionArgs = {
  payer: Address;
  requester: Address;
  ciphertextAccount: Address;
  decryptionRequestAccount: Address;
  /** Caller-chosen 32-byte request id used as PDA seed. */
  requestId: Uint8Array;
};

export function buildRequestDecryptionIx(args: RequestDecryptionArgs): Instruction {
  if (args.requestId.length !== 32) throw new Error('requestId must be 32 bytes');
  const data = new ByteWriter()
    .u8(DISC.REQUEST_DECRYPTION)
    .bytes(args.requestId)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.payer, signer: true, writable: true },
      { address: args.requester, signer: true, writable: false },
      { address: args.ciphertextAccount, writable: false },
      { address: args.decryptionRequestAccount, writable: true },
      { address: SYSTEM_PROGRAM_ID },
    ],
    data
  );
}

export type RespondDecryptionArgs = {
  authority: Address;
  decryptionRequestAccount: Address;
  plaintext: Uint8Array;
};

export function buildRespondDecryptionIx(args: RespondDecryptionArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.RESPOND_DECRYPTION)
    .vec(args.plaintext)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.authority, signer: true, writable: false },
      { address: args.decryptionRequestAccount, writable: true },
    ],
    data
  );
}

export type CloseDecryptionRequestArgs = {
  requester: Address;
  decryptionRequestAccount: Address;
  refundDestination: Address;
};

export function buildCloseDecryptionRequestIx(args: CloseDecryptionRequestArgs): Instruction {
  const data = new ByteWriter().u8(DISC.CLOSE_DECRYPTION_REQUEST).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.requester, signer: true, writable: false },
      { address: args.decryptionRequestAccount, writable: true },
      { address: args.refundDestination, writable: true },
    ],
    data
  );
}
