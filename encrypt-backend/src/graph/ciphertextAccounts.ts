/**
 * Encrypt PDA helpers.
 *
 * Ciphertext and decryption request accounts are explicit accounts in the
 * current Encrypt client model. Callers must supply those account addresses;
 * this module only derives real PDAs documented by the Encrypt program.
 */

import {
  getProgramDerivedAddress,
  getAddressCodec,
  type Address,
  type ProgramDerivedAddress,
} from '@solana/kit';
import { ENCRYPT_PROGRAM_ID } from '../solana/programIds.js';

const enc = new TextEncoder();
const addressCodec = getAddressCodec();

const SEED_CONFIG = enc.encode('encrypt_config');
const SEED_NEK = enc.encode('network_encryption_key');
const SEED_GRAPH = enc.encode('registered_graph');
const SEED_DEPOSIT = enc.encode('encrypt_deposit');
const SEED_AUTHORITY = enc.encode('authority');

export async function deriveEncryptConfigPda(): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ENCRYPT_PROGRAM_ID,
    seeds: [SEED_CONFIG],
  });
}

export async function deriveNetworkEncryptionKeyPda(publicKey: Uint8Array): Promise<ProgramDerivedAddress> {
  if (publicKey.length !== 32) throw new Error('network encryption key must be 32 bytes');
  return getProgramDerivedAddress({
    programAddress: ENCRYPT_PROGRAM_ID,
    seeds: [SEED_NEK, publicKey],
  });
}

export async function deriveRegisteredGraphPda(graphHash: Uint8Array): Promise<ProgramDerivedAddress> {
  if (graphHash.length !== 32) throw new Error('graphHash must be 32 bytes');
  return getProgramDerivedAddress({
    programAddress: ENCRYPT_PROGRAM_ID,
    seeds: [SEED_GRAPH, graphHash],
  });
}

export async function deriveDepositPda(owner: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ENCRYPT_PROGRAM_ID,
    seeds: [SEED_DEPOSIT, new Uint8Array(addressCodec.encode(owner))],
  });
}

export async function deriveAuthorityPda(authority: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ENCRYPT_PROGRAM_ID,
    seeds: [SEED_AUTHORITY, new Uint8Array(addressCodec.encode(authority))],
  });
}
