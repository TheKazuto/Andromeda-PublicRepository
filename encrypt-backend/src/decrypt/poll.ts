/**
 * Poll on-chain DecryptionRequest account to read the response (plaintext)
 * once the executor has processed it.
 *
 * Until the SDK exposes a typed account decoder, we fetch the raw account
 * data and return base64 — the caller is expected to decode according to
 * the documented layout (see book chapter "Account reference -> DecryptionRequest").
 */

import { fetchEncodedAccount, type Address } from '@solana/kit';
import { rpc } from '../solana/connection.js';
import { Errors } from '../lib/errors.js';
import { accountDataToBase64 } from '../lib/responses.js';

export type DecryptionPollResult = {
  exists: boolean;
  lamports: string | null;
  owner: string | null;
  rawDataBase64: string | null;
};

export async function pollDecryption(decryptionRequestPda: Address): Promise<DecryptionPollResult> {
  try {
    const account = await fetchEncodedAccount(rpc, decryptionRequestPda);
    if (!account.exists) {
      return { exists: false, lamports: null, owner: null, rawDataBase64: null };
    }
    return {
      exists: true,
      lamports: account.lamports.toString(),
      owner: String(account.programAddress),
      rawDataBase64: accountDataToBase64(account.data),
    };
  } catch (err) {
    throw Errors.solanaRpc('failed to fetch decryption request account', err);
  }
}
