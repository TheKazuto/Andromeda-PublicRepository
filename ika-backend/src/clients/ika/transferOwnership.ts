/**
 * `transfer_ownership` — Ika dWallet program, instruction discriminator 24.
 *
 * Re-delegates a dWallet's authority to `newAuthority`. The dWallet's CURRENT
 * authority must sign the transaction. We use this to hand a freshly-created
 * MCP dWallet over to the `rules-policy` program's CPI authority PDA, so the
 * policy can mint MessageApprovals on its behalf (`recover_as_primary` /
 * `recover_with_quorum`).
 *
 * This is the DIRECT-call form (the current authority is a real Solana
 * transaction signer), not the CPI form. Wire format verified against the
 * Ika pre-alpha repo:
 *   - chains/solana/examples/voting/native/tests/litesvm.rs::build_transfer_dwallet_ix
 *   - docs/src/on-chain/cpi-framework.md  ("[24, new_authority(32)] = 33 bytes")
 *
 * Accounts (direct call):
 *   0. authority — readonly, signer  (the dWallet's current authority)
 *   1. dwallet   — writable
 */

import { AccountRole, getAddressEncoder } from '@solana/kit'
import type {
  AccountSignerMeta,
  Address,
  Instruction,
  TransactionSigner,
  WritableAccount,
} from '@solana/kit'

/** Ika dWallet program instruction discriminator for `transfer_ownership`. */
export const IKA_IX_TRANSFER_OWNERSHIP = 24

const TRANSFER_OWNERSHIP_DATA_LEN = 33 // disc(1) + new_authority(32)

const addressEncoder = getAddressEncoder()

export interface TransferOwnershipInput {
  /** The Ika dWallet program id. */
  ikaProgramId: Address
  /** The dWallet account whose authority is being transferred. */
  dwallet: Address
  /** The dWallet's current authority — must sign the transaction. */
  authoritySigner: TransactionSigner
  /**
   * The new authority. For delegation to a Quasar policy this is
   * `PDA(["__ika_cpi_authority"], policyProgramId)`.
   */
  newAuthority: Address
}

/**
 * Builds the `transfer_ownership` instruction (33-byte data, 2 accounts).
 *
 * The returned instruction carries the current authority as a signer account,
 * so `signTransactionMessageWithSigners` collects it alongside the fee payer.
 */
export function buildTransferOwnershipInstruction(input: TransferOwnershipInput): Instruction {
  const data = new Uint8Array(TRANSFER_OWNERSHIP_DATA_LEN)
  data[0] = IKA_IX_TRANSFER_OWNERSHIP
  data.set(addressEncoder.encode(input.newAuthority), 1)

  const authorityAccount: AccountSignerMeta = {
    address: input.authoritySigner.address,
    role: AccountRole.READONLY_SIGNER,
    signer: input.authoritySigner,
  }
  const dwalletAccount: WritableAccount = {
    address: input.dwallet,
    role: AccountRole.WRITABLE,
  }

  return {
    programAddress: input.ikaProgramId,
    accounts: [authorityAccount, dwalletAccount],
    data,
  }
}
