// Pure canonical-digest helper for the fhe-gated decision flow.
//
// Kept in its own module (no runtime deps, no config side-effects) so:
//   - the host-side fixture test can import it without booting the rest of
//     the Hono app / Solana RPC client / config validator;
//   - downstream consumers (audit, CLI) can reuse it.
//
// Domain tag MUST stay byte-for-byte identical to:
//   - gateway: gateway/internal/auth/challenges_templates.go::fheGatedDomainDecision
//   - contract: contracts/fhe-gated/src/challenges.rs::DOMAIN_DECISION
// CI runs all three suites against fixtures/fhe-decision-vectors.json — any
// drift here breaks every fhe-gated request_signature on devnet.

import { createHash } from 'node:crypto';

export const DECISION_DOMAIN = Buffer.from('andromeda::fhe-gated::decision::v1');

/**
 * decisionCanonicalBytes — 32-byte digest the Vault Transit `andromeda-fhe`
 * Ed25519 key signs. The on-chain handler recomputes the same digest and
 * matches it against the Ed25519 precompile invocation in the same tx.
 *
 * Layout (mirrors contracts/fhe-gated/src/challenges.rs::decision_canonical_bytes):
 *   sha256(
 *     "andromeda::fhe-gated::decision::v1" ||
 *     policy(32) ||
 *     message_digest(32) ||
 *     decision_created_slot(u64 LE) ||
 *     decision_authorize(u8)
 *   )
 */
export function decisionCanonicalBytes(
  policy: Uint8Array,
  messageDigest: Uint8Array,
  decisionCreatedSlot: bigint,
  decisionAuthorize: number,
): Buffer {
  if (policy.length !== 32) throw new Error('policy must be 32 bytes');
  if (messageDigest.length !== 32) throw new Error('message_digest must be 32 bytes');
  const slot = Buffer.alloc(8);
  slot.writeBigUInt64LE(decisionCreatedSlot);
  const auth = Buffer.from([decisionAuthorize & 0xff]);
  return createHash('sha256')
    .update(DECISION_DOMAIN)
    .update(policy)
    .update(messageDigest)
    .update(slot)
    .update(auth)
    .digest();
}
