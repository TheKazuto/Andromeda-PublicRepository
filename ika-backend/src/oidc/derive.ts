/**
 * Login Social (`scheme = 4 = OidcJwt`) — TypeScript mirrors of the on-chain
 * derivations in `contracts/oidc-verifier` (`addr_seed`, `oidc_nonce`) and the
 * JWK-registry lookup hashes, plus the `subjectHash` used in logs/metrics.
 *
 * Wire formats are FROZEN (loginsocial.md §6.3/§6.4/§12 + `OIDC_VERIFIER_V1`).
 * Any change here MUST be matched in `contracts/oidc-verifier/src/lib.rs` and
 * `contracts/rules-policy/src/lib.rs` in the same commit.
 *
 * The `oidc-session-open` / `oidc-primary-use` challenges live in
 * `../recovery/challenge.ts` (already byte-mirrored against `contracts/auth`).
 */

import { createHash, createHmac } from 'node:crypto'

const enc = new TextEncoder()

/** `SHA256("andromeda::oidc::addr::v1" || ...)` domain tag. */
export const OIDC_ADDR_DOMAIN = enc.encode('andromeda::oidc::addr::v1')
/** `SHA256("andromeda::oidc::nonce::v1" || ...)` domain tag. */
export const OIDC_NONCE_DOMAIN = enc.encode('andromeda::oidc::nonce::v1')

/** Length of the canonical base64url-no-pad `oidc_nonce` (32 bytes → 43 chars). */
export const OIDC_NONCE_B64_LEN = 43
/** `addr_seed` / each hash is a 32-byte SHA-256 digest. */
export const OIDC_HASH_LEN = 32

function sha256v(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

/** `SHA-256(data)`. */
export function sha256(data: Uint8Array): Uint8Array {
  return sha256v(data)
}

function u16le(v: number): Uint8Array {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff) {
    throw new Error(`u16le out of range: ${v}`)
  }
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, v, true)
  return b
}

function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`u64le out of range: ${v}`)
  }
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, v, true)
  return b
}

/** UTF-8 bytes of a claim string. */
function utf8(s: string): Uint8Array {
  return enc.encode(s)
}

/**
 * `addr_seed = SHA256("andromeda::oidc::addr::v1" || u16le(len(iss)) || iss ||
 *  u16le(len(aud)) || aud || u16le(len(sub)) || sub)` — length-prefixed so the
 * concatenation is unambiguous. Mirrors `oidc_verifier::derive_addr_seed`.
 */
export function deriveAddrSeed(iss: string, aud: string, sub: string): Uint8Array {
  const i = utf8(iss)
  const a = utf8(aud)
  const s = utf8(sub)
  return sha256v(OIDC_ADDR_DOMAIN, u16le(i.length), i, u16le(a.length), a, u16le(s.length), s)
}

/** The canonical OIDC primary slot `[4, addr_seed(32), 0]` (34 bytes). */
export function oidcPrimarySlotBytes(addrSeed: Uint8Array): Uint8Array {
  if (addrSeed.length !== OIDC_HASH_LEN) {
    throw new Error(`addr_seed must be ${OIDC_HASH_LEN} bytes, got ${addrSeed.length}`)
  }
  const slot = new Uint8Array(34)
  slot[0] = 4 // SCHEME_OIDC_JWT
  slot.set(addrSeed, 1)
  return slot
}

/**
 * `oidc_nonce = base64url_nopad( SHA256("andromeda::oidc::nonce::v1" || eph_pk(32)
 *  || u64le(not_after_unix_ts) || nonce_randomness(32)) )` — 43 chars.
 * Mirrors `oidc_verifier::recompute_oidc_nonce`.
 */
export function deriveOidcNonce(
  ephPk: Uint8Array,
  notAfterUnixTs: bigint,
  nonceRandomness: Uint8Array,
): string {
  if (ephPk.length !== 32) throw new Error(`eph_pk must be 32 bytes, got ${ephPk.length}`)
  if (nonceRandomness.length !== 32) {
    throw new Error(`nonce_randomness must be 32 bytes, got ${nonceRandomness.length}`)
  }
  const digest = sha256v(OIDC_NONCE_DOMAIN, ephPk, u64le(notAfterUnixTs), nonceRandomness)
  return Buffer.from(digest).toString('base64url')
}

/** `sha256(utf8(iss))` — JWK-registry lookup component. */
export function issuerHash(iss: string): Uint8Array {
  return sha256(utf8(iss))
}

/** `sha256(utf8(aud))` — JWK-registry lookup component. */
export function audienceHash(aud: string): Uint8Array {
  return sha256(utf8(aud))
}

/** `sha256(utf8(kid))` — JWK-registry lookup component. */
export function kidHash(kid: string): Uint8Array {
  return sha256(utf8(kid))
}

/**
 * `subjectHash = HMAC-SHA256(secret, utf8(iss) || 0x00 || utf8(aud) || 0x00 ||
 *  utf8(sub))` — a stable, non-reversible identifier for logs/metrics
 * (loginsocial.md §12). Never log the raw `sub`.
 */
export function subjectHash(secret: string, iss: string, aud: string, sub: string): Uint8Array {
  const h = createHmac('sha256', secret)
  h.update(utf8(iss))
  h.update(Uint8Array.of(0))
  h.update(utf8(aud))
  h.update(Uint8Array.of(0))
  h.update(utf8(sub))
  return new Uint8Array(h.digest())
}

/** `Uint8Array` → base64 (for API responses / logs of hash digests). */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}
