/**
 * Encrypt program instruction discriminators (Solana, pre-alpha).
 *
 * Source: encrypt-pre-alpha repo `chains/solana/program/src/instruction.rs`
 * and the published Instruction reference in the developer guide.
 *
 * Layout: first byte of instruction data = discriminator. Remaining bytes are
 * the BCS-serialized arguments specific to each instruction.
 */

export const DISC = {
  // Setup
  INITIALIZE: 0,

  // Executor (1..6)
  CREATE_INPUT_CIPHERTEXT: 1,
  CREATE_PLAINTEXT_CIPHERTEXT: 2,
  COMMIT_CIPHERTEXT: 3,
  EXECUTE_GRAPH: 4,
  REGISTER_GRAPH: 5,
  EXECUTE_REGISTERED_GRAPH: 6,

  // Ownership (7..9)
  TRANSFER_CIPHERTEXT: 7,
  COPY_CIPHERTEXT: 8,
  MAKE_PUBLIC: 9,

  // Gateway / decryption (10..12)
  REQUEST_DECRYPTION: 10,
  RESPOND_DECRYPTION: 11,
  CLOSE_DECRYPTION_REQUEST: 12,

  // Fees (13..18)
  CREATE_DEPOSIT: 13,
  TOP_UP: 14,
  WITHDRAW: 15,
  UPDATE_CONFIG_FEES: 16,
  REIMBURSE: 17,
  REQUEST_WITHDRAW: 18,

  // Authority (19..21)
  ADD_AUTHORITY: 19,
  REMOVE_AUTHORITY: 20,
  REGISTER_NETWORK_ENCRYPTION_KEY: 21,

  // Events
  EMIT_EVENT: 228,
} as const;

export type Discriminator = (typeof DISC)[keyof typeof DISC];

export const DISC_NAME: Record<number, string> = Object.fromEntries(
  Object.entries(DISC).map(([k, v]) => [v, k])
);
