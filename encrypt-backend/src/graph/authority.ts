/**
 * Authority management instructions (disc 19..21) and event (228).
 */

import type { Address, Instruction } from '@solana/kit';
import { ByteWriter } from '../lib/serialization.js';
import { DISC } from './discriminators.js';
import { ENCRYPT_PROGRAM_ID, SYSTEM_PROGRAM_ID } from '../solana/programIds.js';
import { makeInstruction } from '../solana/instructions.js';
import { getAddressCodec } from '@solana/kit';

const addressCodec = getAddressCodec();

export type AddAuthorityArgs = {
  admin: Address;
  newAuthority: Address;
  authorityPda: Address;
};

export function buildAddAuthorityIx(args: AddAuthorityArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.ADD_AUTHORITY)
    .bytes(new Uint8Array(addressCodec.encode(args.newAuthority)))
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.admin, signer: true, writable: true },
      { address: args.authorityPda, writable: true },
      { address: SYSTEM_PROGRAM_ID },
    ],
    data
  );
}

export type RemoveAuthorityArgs = {
  admin: Address;
  authorityPda: Address;
};

export function buildRemoveAuthorityIx(args: RemoveAuthorityArgs): Instruction {
  const data = new ByteWriter().u8(DISC.REMOVE_AUTHORITY).build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.admin, signer: true, writable: false },
      { address: args.authorityPda, writable: true },
    ],
    data
  );
}

export type RegisterNetworkEncryptionKeyArgs = {
  payer: Address;
  authority: Address;
  nekPda: Address;
  publicKey: Uint8Array; // 32 bytes
};

export function buildRegisterNetworkEncryptionKeyIx(
  args: RegisterNetworkEncryptionKeyArgs
): Instruction {
  if (args.publicKey.length !== 32) throw new Error('NEK public key must be 32 bytes');
  const data = new ByteWriter()
    .u8(DISC.REGISTER_NETWORK_ENCRYPTION_KEY)
    .bytes(args.publicKey)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [
      { address: args.payer, signer: true, writable: true },
      { address: args.authority, signer: true, writable: false },
      { address: args.nekPda, writable: true },
      { address: SYSTEM_PROGRAM_ID },
    ],
    data
  );
}

export type EmitEventArgs = {
  emitter: Address;
  eventBytes: Uint8Array;
};

export function buildEmitEventIx(args: EmitEventArgs): Instruction {
  const data = new ByteWriter()
    .u8(DISC.EMIT_EVENT)
    .vec(args.eventBytes)
    .build();

  return makeInstruction(
    ENCRYPT_PROGRAM_ID,
    [{ address: args.emitter, signer: true, writable: false }],
    data
  );
}
