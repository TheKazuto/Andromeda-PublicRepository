/**
 * Wrapper around @encrypt.xyz/pre-alpha-solana-client gRPC client.
 *
 * The upstream package exposes `createEncryptClient` from
 * `@encrypt.xyz/pre-alpha-solana-client/grpc` and a `Chain` enum (`Chain.Solana = 0`).
 *
 * Because the package is in pre-alpha and its API surface may shift, we
 * import it dynamically and keep our own typed facade so the rest of the
 * backend does not depend on Encrypt's exact export shape.
 */

import { config } from '../config.js';
import { logger } from '../lib/logger.js';
import { Errors } from '../lib/errors.js';
import { withTimeout } from '../lib/timeout.js';

export type EncryptedInputPayload = {
  ciphertextBytes: Uint8Array;
  fheType: number;
};

export type CreateInputArgs = {
  inputs: EncryptedInputPayload[];
  authorized: Uint8Array;
  networkEncryptionPublicKey: Uint8Array;
  proof?: Uint8Array;
};

export type CreateInputResult = {
  ciphertextIdentifiers: Uint8Array[];
};

export type ReadCiphertextArgs = {
  message: Uint8Array;
  signature: Uint8Array;
  signer: Uint8Array;
};

export type ReadCiphertextResult = {
  value: Uint8Array;
  fheType: number;
  digest: Uint8Array;
};

type RawEncryptClient = {
  createInput: (args: {
    chain: number;
    inputs: { ciphertextBytes: Uint8Array; fheType: number }[];
    authorized: Uint8Array;
    networkEncryptionPublicKey: Uint8Array;
    proof?: Uint8Array;
  }) => Promise<{ ciphertextIdentifiers: Uint8Array[] }>;
  readCiphertext: (args: {
    message: Uint8Array;
    signature: Uint8Array;
    signer: Uint8Array;
  }) => Promise<{ value: Uint8Array; fheType: number; digest: Uint8Array }>;
  close?: () => void;
};

let cachedClient: RawEncryptClient | null = null;
let initPromise: Promise<RawEncryptClient> | null = null;

const CHAIN_SOLANA = 0;

async function loadClient(): Promise<RawEncryptClient> {
  if (cachedClient) return cachedClient;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const grpcModuleUrl = new URL(
        '../../node_modules/@encrypt.xyz/pre-alpha-solana-client/dist/grpc.js',
        import.meta.url
      );
      const mod = await import(grpcModuleUrl.href);
      const factory = (mod as { createEncryptClient: (grpcUrl?: string) => RawEncryptClient })
        .createEncryptClient;
      if (typeof factory !== 'function') {
        throw new Error('createEncryptClient is not a function — Encrypt SDK shape changed');
      }
      const grpcUrl = normalizeGrpcUrl(config.ENCRYPT_GRPC_URL);
      const client = factory(grpcUrl);
      cachedClient = client;
      logger.info({ url: grpcUrl }, 'Encrypt gRPC client initialized');
      return client;
    } catch (err) {
      initPromise = null;
      logger.error({ err }, 'Failed to initialize Encrypt gRPC client');
      throw Errors.encryptGrpc('Failed to initialize Encrypt gRPC client', err);
    }
  })();

  return initPromise;
}

function normalizeGrpcUrl(url: string): string {
  return url.replace(/^https?:\/\//, '');
}

export async function getEncryptClient(): Promise<RawEncryptClient> {
  return loadClient();
}

export async function callCreateInput(args: CreateInputArgs): Promise<CreateInputResult> {
  const client = await loadClient();
  try {
    const res = await withTimeout(
      client.createInput({
        chain: CHAIN_SOLANA,
        inputs: args.inputs,
        authorized: args.authorized,
        networkEncryptionPublicKey: args.networkEncryptionPublicKey,
        proof: args.proof,
      }),
      config.ENCRYPT_GRPC_TIMEOUT_MS,
      'CreateInput timed out'
    );
    return { ciphertextIdentifiers: res.ciphertextIdentifiers };
  } catch (err) {
    throw Errors.encryptGrpc('CreateInput failed', err);
  }
}

export async function callReadCiphertext(args: ReadCiphertextArgs): Promise<ReadCiphertextResult> {
  const client = await loadClient();
  try {
    const res = await withTimeout(
      client.readCiphertext({
        message: args.message,
        signature: args.signature,
        signer: args.signer,
      }),
      config.ENCRYPT_GRPC_TIMEOUT_MS,
      'ReadCiphertext timed out'
    );
    return { value: res.value, fheType: res.fheType, digest: res.digest };
  } catch (err) {
    throw Errors.encryptGrpc('ReadCiphertext failed', err);
  }
}

export async function pingEncryptGrpc(): Promise<boolean> {
  try {
    await loadClient();
    return true;
  } catch {
    return false;
  }
}

/**
 * Eagerly initialize the gRPC client at boot so the first user request does
 * not pay the dynamic import + handshake cost. Errors are swallowed (logged
 * upstream by loadClient) — the next real call will retry.
 */
export async function preWarmEncryptClient(): Promise<void> {
  try {
    await loadClient();
  } catch (err) {
    logger.warn({ err }, 'Encrypt gRPC pre-warm failed (will retry on demand)');
  }
}
