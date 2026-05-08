// readPolicyAccount: high-level helper that fetches a policy account from
// Solana and decodes it via the template-specific decoder. Mirrors what the
// gateway test scripts do (scripts/test_read_policy.go), but typed for the
// recovery layer's TS surface.

import { Buffer } from 'node:buffer';

import {
  type Address,
  type GetAccountInfoApi,
  type Rpc,
} from '@solana/kit';

import {
  decodePolicyState,
  type AnyPolicyState,
  type TemplateName,
} from './readState.js';

export interface ReadPolicyAccountResult {
  exists: true;
  programId: Address;
  state: AnyPolicyState;
  rentLamports: bigint;
  dataLen: number;
}

export interface ReadPolicyAccountMissing {
  exists: false;
}

export type ReadPolicyAccountResponse = ReadPolicyAccountResult | ReadPolicyAccountMissing;

/**
 * Fetches the on-chain policy account at `policyAddress`, validates that the
 * account is owned by `expectedProgramId`, and decodes its data via the
 * `template`-specific decoder. Returns `{ exists: false }` when the account
 * does not exist.
 *
 * Designed for the recovery layer's `policy_subscriptions` lookup pattern:
 * given (policy_address, template, program_id) you've persisted at init/prepare,
 * call this to get the live policy state without re-deriving anything.
 */
export async function readPolicyAccount(
  rpc: Rpc<GetAccountInfoApi>,
  policyAddress: Address,
  template: TemplateName,
  expectedProgramId: Address,
): Promise<ReadPolicyAccountResponse> {
  const result = await rpc
    .getAccountInfo(policyAddress, { encoding: 'base64', commitment: 'confirmed' })
    .send();
  if (!result.value) {
    return { exists: false };
  }

  if ((result.value.owner as string) !== (expectedProgramId as string)) {
    throw new Error(
      `policy ${policyAddress} owner ${String(result.value.owner)} != expected ${String(expectedProgramId)}`,
    );
  }

  const dataField = result.value.data;
  const base64 = Array.isArray(dataField) ? dataField[0] : dataField;
  if (typeof base64 !== 'string') {
    throw new Error(`unexpected getAccountInfo data shape for ${policyAddress}`);
  }
  const raw = Uint8Array.from(Buffer.from(base64, 'base64'));
  const state = decodePolicyState(template, raw);
  return {
    exists: true,
    programId: expectedProgramId,
    state,
    rentLamports: result.value.lamports,
    dataLen: raw.length,
  };
}
