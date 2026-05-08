/**
 * High-level CreateInput orchestrator. Combines:
 *   - NEK fetch (cached)
 *   - authorized field normalization
 *   - gRPC call to Encrypt executor
 *   - response shaping for HTTP layer
 */

import { callCreateInput } from './client.js';
import { getCurrentNek } from './nek.js';
import { authorizedFromAddress, authorizedFromBytes } from './authorized.js';
import { encodeBase64 } from '../lib/validation.js';

export type CreateInputItem = {
  /** raw ciphertext bytes (already produced by an off-chain encryption helper) */
  ciphertextBytes: Uint8Array;
  /** numeric FHE type id — see Encrypt DSL reference */
  fheType: number;
};

export type CreateInputOptions = {
  inputs: CreateInputItem[];
  /** either a base58 Solana address OR explicit 32-byte authorized value */
  authorizedAddress?: string;
  authorizedBytes?: Uint8Array;
  /** optional precomputed proof bytes; in mock mode the executor skips proof */
  proof?: Uint8Array;
};

export type CreateInputResponse = {
  identifiers: string[]; // base64
  count: number;
  nek: {
    publicKey: string;
    source: string;
  };
};

export async function createInputCiphertexts(
  opts: CreateInputOptions
): Promise<CreateInputResponse> {
  const nek = await getCurrentNek();

  const authorized = opts.authorizedBytes
    ? authorizedFromBytes(opts.authorizedBytes)
    : opts.authorizedAddress
      ? authorizedFromAddress(opts.authorizedAddress)
      : nek.publicKey; // safe default: NEK itself acts as authorized in basic flows

  const result = await callCreateInput({
    inputs: opts.inputs,
    authorized,
    networkEncryptionPublicKey: nek.publicKey,
    proof: opts.proof,
  });

  return {
    identifiers: result.ciphertextIdentifiers.map(encodeBase64),
    count: result.ciphertextIdentifiers.length,
    nek: { publicKey: nek.publicKeyBase64, source: nek.source },
  };
}
