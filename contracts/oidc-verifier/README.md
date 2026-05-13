# `andromeda_oidc_verifier` — on-chain OIDC JWT verifier (`no_std` lib)

The cryptographic core of the **Login Social** feature ("Caminho A" — `loginsocial.md` §2, §6, §7.2). A pure `no_std` library (no program, no account, no CPI) consumed by `contracts/rules-policy/` when opening an `OidcSession` (`scheme = 4 = OidcJwt`).

```
verify(VerifyOidcInput {
    jwt,                 // header.payload.signature, from rules-policy's OidcJwtStaging account
    modulus_n,           // RSA-2048 modulus (256 BE bytes) — from the ACTIVE jwk-registry entry
    exponent_e,          // must be 65537
    allowed_issuers,     // env allowlist (e.g. ["https://accounts.google.com", "https://appleid.apple.com"])
    allowed_audiences,   // env allowlist = the auth-broker client_id(s)
    eph_pk, not_after_unix_ts, nonce_randomness,   // from the instruction data — recompose oidc_nonce
    now_unix_ts,         // Clock sysvar
}) -> Result<ParsedOidc { addr_seed, issuer_hash, audience_hash, kid_hash, jwt_digest, exp_unix_ts }, OidcVerifyError>
```

## What `verify` does (and the order — it matters)

1. **pre-checks** — JWT non-empty & ≤ 4 KiB; `exponent_e == 65537`; `modulus_n` exactly 256 bytes, full 2048-bit (top bit set), odd; non-empty allowlists.
2. **split** `header.payload.signature` (exactly two dots, all three segments non-empty).
3. **base64url decode** each segment, strictly (alphabet `A-Za-z0-9-_` only — no `=`/`+`/`/`; reject `len ≡ 1 (mod 4)`; reject non-canonical trailing bits; bounded buffers: header ≤ 256 B, payload ≤ 1024 B, signature exactly 256 B).
4. **strict parse** of the JOSE header — `alg == "RS256"`, a non-empty `kid`, **no `crit`/`jku`/`x5u`** (or any remote-key header), no duplicate keys, no backslash escapes in the values — and of the claims — `iss`, `aud`, `sub`, `nonce` (strings; **`aud` only as a string**, an array `aud` is rejected; no backslash escapes), `iat`, `exp` (plain non-negative decimal integers — no floats, no scientific notation, no leading zeros, bounded length), optional `nbf`; no duplicate keys; values *anchored* to their `"key":` (never substring-matched). **No auth decision is made here** — these values are untrusted until step 5.
5. **RSA verify** — `recovered = signature^65537 mod modulus_n` via the `sol_big_mod_exp` syscall; build the *expected* EMSA-PKCS1-v1_5(SHA-256) block `00 01 || FF*202 || 00 || DigestInfo(SHA-256) || SHA-256(header.payload)`; require `recovered == EM` over **all 256 bytes** (no early return). Rejects the Bleichenbacher / "BERserk" family. Also rejects `signature ≥ modulus_n`. *(`jwt_digest = SHA-256(header.payload)` is returned for the `oidc-session-open` challenge.)*
6. **(claims now authentic)** recompute `oidc_nonce = base64url_nopad(SHA-256("andromeda::oidc::nonce::v1" || eph_pk || not_after_unix_ts_le(u64) || nonce_randomness))` (43 chars) and require the `nonce` claim equals it.
7. `iss`/`aud` against the allowlists (exact); `exp > now`; `exp >= not_after_unix_ts`; `iat <= now + 300s`; `nbf <= now + 300s` (if present); `0 <= exp - iat <= 4h`.
8. derive `addr_seed = SHA-256("andromeda::oidc::addr::v1" || u16le(len(iss)) || iss || u16le(len(aud)) || aud || u16le(len(sub)) || sub)` (length-prefixed → unambiguous), `issuer_hash/audience_hash/kid_hash = SHA-256(...)`.

Versioned by `OIDC_VERIFIER_V1 = 1` — bump on any wire/derivation change.

## SHA-256 / big-mod-exp: syscall on SBF, real crates on the host

The SBF build uses the `sol_sha256` and `sol_big_mod_exp` syscalls (no deps). The host build (for `cargo test` / `cargo check`) uses `sha2` and `num-bigint` so unit tests compute the same digests/modexp the runtime would — neither crate is pulled into the SBF artifact (`[target.'cfg(not(target_os = "solana"))'.dependencies]`).

## CU / size (measured — `loginsocial-spike`, `solana-program-test` SBF)

`sol_big_mod_exp` (RSA-2048, `e = 65537`) ≈ ~33k CU; full `verify` (SHA-256 of ~700–1100 B + PKCS#1 build + RSA + 256-byte compare + JSON parse + nonce recompute + `addr_seed`) ≈ ~41k CU. `verify`'s stack frame ≈ ~2.4 KB (bounded buffers), well under the 4 KB BPF limit. **CU re-profiling in the `rules-policy` / litesvm harness is a Fase 2/3 item** (the spike was a standalone program; the lib's profile should match).

## Tests

`cargo test` (host): base64url decode (round-trips + canonical-form + alphabet + length rejections), JWT split, strict header parsing (missing/dup `alg`/`kid`, `alg != RS256`, `crit`/`jku`/`x5u`, backslash, trailing junk), strict claims parsing (missing/dup claims, array `aud`, string-vs-number `iat`, float/leading-zero `iat`, backslash in `iss`, `nbf`), `oidc_nonce` / `addr_seed` determinism + length-prefix unambiguity, `verify` pre-checks. The full positive path (a real RS256-signed JWT accepted) is exercised via `fixtures/oidc/v1/` + the `rules-policy` / litesvm integration tests once `fixtures/oidc/v1/gen.ts` exists (deferred — see `fixtures/oidc/v1/README.md`).

## Security audit

Required before deploy — `docs/AUDIT_CHECKLIST_OIDC.md` §2. Focus: malicious JSON (the `claims.rs` scanner), PKCS#1 padding oracle / forgery families (`pkcs1.rs`), bounds, the strict no-auth-before-RSA ordering in `verify`.

## Consumers

`contracts/rules-policy/` (Fase 3) — `oidc_session_open` calls `verify(...)` with the JWT from `OidcJwtStaging` and `n`/`e` from the ACTIVE `JwkRegistry` entry; `OidcSession` stores the resulting `addr_seed`/hashes/`jwt_digest`; `recover_as_primary_oidc_session` re-checks the JWK entry status on every use. The TS mirror of the `oidc_nonce` / `addr_seed` derivations lives in `packages/andromeda-oidc-sdk/` and `ika-backend/src/oidc/` (Fase 4/6); golden vectors in `fixtures/oidc/v1/challenge_vectors.json`.
