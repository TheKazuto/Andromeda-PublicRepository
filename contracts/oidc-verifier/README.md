# `andromeda_oidc_verifier` — on-chain OIDC JWT verifier (`no_std` lib)

The cryptographic core of the **Login Social** path. A pure `no_std` library (no program, no account, no CPI) consumed by `contracts/policy-engine/` when opening the OIDC primary session (`scheme = 4 = OidcJwt`).

```rust
verify(VerifyOidcInput {
    jwt,                 // header.payload.signature, ASCII bytes
    modulus_n,           // RSA-2048 modulus (256 BE bytes) — from the ACTIVE jwk-registry entry
    exponent_e,          // must be 65_537
    allowed_issuers,     // env allowlist (e.g. ["https://accounts.google.com", "https://appleid.apple.com"])
    allowed_audiences,   // env allowlist = the auth-broker client_id(s)
    eph_pk, not_after_unix_ts, nonce_randomness,   // from the instruction data — recomposes oidc_nonce
    now_unix_ts,         // Clock sysvar
})
// -> Result<ParsedOidc { addr_seed, issuer_hash, audience_hash, kid_hash, jwt_digest, exp_unix_ts },
//           OidcVerifyError>
```

`VerifyOidcInput` has a manual `Debug` impl that redacts the raw JWT bytes and `nonce_randomness` (so a stray `{:?}` upstream cannot leak the token).

## What `verify` does (and the order — it matters)

1. **pre-checks** — JWT non-empty & ≤ 4 KiB; `exponent_e == 65_537`; `modulus_n` exactly 256 bytes, full 2048-bit (top bit set), odd; non-empty allowlists.
2. **split** `header.payload.signature` (exactly two dots, all three segments non-empty).
3. **base64url decode** each segment, strictly (alphabet `A-Za-z0-9-_` only — no `=`/`+`/`/`; reject `len ≡ 1 (mod 4)`; reject non-canonical trailing bits; bounded buffers: header ≤ 256 B, payload ≤ 1024 B, signature exactly 256 B).
4. **strict parse** of the JOSE header — `alg == "RS256"`, a non-empty `kid`, **no `crit`/`jku`/`x5u`**, no duplicate keys, no backslash escapes in the values — and of the claims — `iss`, `aud`, `sub`, `nonce` (strings; **`aud` only as a string**, an array `aud` is rejected; no backslash escapes), `iat`, `exp` (plain non-negative decimal integers — no floats, no scientific notation, no leading zeros, bounded length), optional `nbf`; no duplicate keys; values *anchored* to their `"key":` (never substring-matched); JSON nesting capped at 16 levels. **No auth decision is made here** — these values are untrusted until step 5.
5. **RSA verify** — `recovered = signature^65537 mod modulus_n` via the `sol_big_mod_exp` syscall (wrapped by `pkcs1::rsa2048_modexp`, which returns a `Result<[u8; 256], OidcVerifyError>` — see "Feature `oidc-rsa`" below); build the *expected* EMSA-PKCS1-v1_5(SHA-256) block `00 01 || FF*202 || 00 || DigestInfo(SHA-256) || SHA-256(header.payload)`; require `recovered == EM` over **all 256 bytes** branchless (no early return, no data-dependent branch on the final equality). Also rejects `signature ≥ modulus_n` (constant-flow big-endian compare). *(`jwt_digest = SHA-256(header.payload)` is returned for the `oidc-session-open` challenge.)*
6. **(claims are authentic from here on)** reject pathologically short values (`iss` < 8 chars, `aud` < 4, `sub` < 6); recompute `oidc_nonce = base64url_nopad(SHA-256("andromeda::oidc::nonce::v1" || eph_pk || not_after_unix_ts_le(u64) || nonce_randomness))` (43 chars) and require the `nonce` claim equals it byte-for-byte (constant-time).
7. `iss`/`aud` against the allowlists (constant-flow exact membership); `exp > now`; `exp >= not_after_unix_ts`; `iat <= now + 300s`; `nbf <= now + 300s` (if present); `0 <= exp - iat <= 4h`.
8. derive `addr_seed = SHA-256("andromeda::oidc::addr::v1" || u16le(len(iss)) || iss || u16le(len(aud)) || aud || u16le(len(sub)) || sub)` (length-prefixed → unambiguous), `issuer_hash/audience_hash/kid_hash = SHA-256(...)`.

Versioned by `OIDC_VERIFIER_V1 = 1` — bump on any wire/derivation change.

## Feature `oidc-rsa`

Default ON. When OFF (e.g. when building for a Solana cluster where the `sol_big_mod_exp` syscall is not yet active — devnet pre-alpha), `pkcs1::rsa2048_modexp` returns `Err(OidcVerifyError::BadSignature)` explicitly. Every `verify` call rejects at step 5; Login Social via OIDC is unavailable until the program is rebuilt with the feature on.

The host build (`cargo test` / `cargo check`) always computes the modexp via `num-bigint` regardless of the feature, so unit tests run identically.

## SHA-256 / big-mod-exp: syscall on SBF, real crates on the host

The SBF build uses the `sol_sha256` and `sol_big_mod_exp` syscalls (no deps). The host build (for tests) uses `sha2` and `num-bigint`, so unit tests compute the same digests/modexp the runtime would. Neither crate is pulled into the SBF artifact (`[target.'cfg(not(target_os = "solana"))'.dependencies]`).

## Tests

`cargo test` (host):

- base64url decode — round-trips, canonical-form, alphabet, length rejections.
- JWT split — exact two-dot rule.
- Strict header parsing — missing/dup `alg`/`kid`, `alg != RS256`, `crit`/`jku`/`x5u`, backslash, trailing junk.
- Strict claims parsing — missing/dup claims, array `aud`, string-vs-number `iat`, float/leading-zero `iat`, backslash in `iss`, `nbf`.
- `oidc_nonce` / `addr_seed` — determinism + length-prefix unambiguity.
- `verify` pre-checks.
- Full happy paths (real RS256-signed JWTs) — Google + Apple flavors.

14 tests, all passing on host. The full SBF positive path runs inside `contracts/sbf-tests` once the devnet `sol_big_mod_exp` syscall ships.

## Consumers

- `contracts/policy-engine/` — the OIDC session-open handler calls `verify(...)` with the JWT and the `n`/`e` from the ACTIVE `JwkRegistry` entry; the session PDA stores the resulting `addr_seed` / hashes / `jwt_digest`. The per-use OIDC primary handler re-checks the JWK entry status on every use.
- TS mirror of the `oidc_nonce` / `addr_seed` derivations: `ika-backend/src/oidc/`.
- Golden vectors: `fixtures/oidc/v1/challenge_vectors.json`.
