# jwk-rotator

Off-chain watcher for the Andromeda `jwk-registry` Solana program (`contracts/jwk-registry/`). Fetches the Google / Apple JWKS over TLS, diffs against the on-chain registry, and **proposes** new keys with the `authority` keypair. **Never activates / revokes / expires** — those are human (or multisig) actions after the on-chain timelock.

Used by **Login Social** (`loginsocial.md` §8): the on-chain registry is the trust root for the RSA public keys used to verify Google / Apple `id_token`s. Without this watcher running, new keys Google rotates in (every ~2 weeks) require manual `propose_jwk` calls; ACTIVE keys that disappear from the JWKS go unnoticed.

Stack: Node ≥ 20 · TypeScript · `tsx` · `@solana/web3.js` · Railway worker.

## Communicates with

- **Google JWKS** — `https://www.googleapis.com/oauth2/v3/certs` (TLS, public).
- **Apple JWKS** — `https://appleid.apple.com/auth/keys` (TLS, public; disabled by default).
- **Solana RPC** — reads the on-chain `JwkRegistry` account, sends `propose_jwk` transactions signed by the `authority` keypair.
- **Alert webhook** (optional) — Discord / Slack-compatible URL for ops notifications.

```
                    ┌── Google JWKS ──┐
[jwk-rotator]──┤                  │── diff vs. on-chain ──▶ propose_jwk
                    └── Apple JWKS ───┘                            │
                                                              alert ops
                                                              (webhook / stdout)
```

## Project layout

```
jwk-rotator/
├── src/index.ts          single-file watcher + bootstrap one-shot
├── package.json
├── tsconfig.json
├── .env.example
├── .env                  (local, gitignored)
└── .gitignore
```

## Modes

| Mode | Command | When to use |
|---|---|---|
| **`start`** (default) | `npm run start` | Long-running. Polls every `POLL_INTERVAL_SECONDS` (default 1h). For production, deploy as a worker. |
| **`once`** | `npm run once` | One iteration, then exit. Useful for cron or manual checks. |
| **`bootstrap`** | `npm run bootstrap` | One-time devnet genesis. Dry-run: prints the `init_registry` + `bootstrap_jwk` instructions in JSON. |
| **`bootstrap:send`** | `npm run bootstrap:send` | Same as above but submits the transactions on-chain. Requires a payer keypair DISTINCT from the authority (see runbook §0). |

## Local dev

```bash
cd jwk-rotator
npm install
cp .env.example .env
# fill .env with your devnet values + JWK_AUTHORITY_KEYPAIR pointing at a local file
npm run once
```

For the bootstrap (one-time only — `bootstrap_jwk` requires `entry_count == 0`):

```bash
npm run bootstrap                # dry-run — prints JSON
npm run bootstrap:send           # actually submits
```

## Env vars

See `.env.example` for the canonical list. Highlights:

| Var | Required | Default | Purpose |
|---|---|---|---|
| `RPC_URL` | yes | — | Solana RPC endpoint. |
| `JWK_REGISTRY_PROGRAM_ID` | yes | — | The deployed `jwk-registry` program ID (devnet: `8xL2mrQ2amDpinQMHJPaEELbgEXWRVGn4PQ7kzDm7vNM`). |
| `JWK_REGISTRY_SEED` | no | 32 zeros | Hex-encoded 32-byte registry seed. The canonical seed is all-zero. |
| `JWK_AUTHORITY_KEYPAIR` | one of the two | — | File path to the authority keypair JSON. Local dev. |
| `JWK_AUTHORITY_KEYPAIR_JSON` | one of the two | — | Inline JSON array of 64 bytes. Takes precedence over the file path. Use this on Railway / PaaS. |
| `POLL_INTERVAL_SECONDS` | no | `3600` | Watcher loop interval. |
| `GOOGLE_ENABLED` | no | `true` | Enable the Google provider. |
| `GOOGLE_AUDIENCE` | yes if Google enabled | — | The auth-broker `client_id` registered at Google. Must equal the on-chain `OIDC_ALLOWED_AUDIENCES` in `rules-policy`. |
| `APPLE_ENABLED` | no | `true` | Enable the Apple provider. |
| `APPLE_AUDIENCE` | yes if Apple enabled | — | Apple Services ID. |
| `ALERT_WEBHOOK_URL` | no | — | POST destination for alerts. Empty = stdout only. |
| `SUCCESSOR_WARN_DAYS` | no | `7` | Warn when an ACTIVE entry is within this window of `valid_until_ts` and has no PENDING / ACTIVE successor. |

Bootstrap-mode extras (ignored in watcher mode):

| Var | Required for `bootstrap:send` | Purpose |
|---|---|---|
| `JWK_REGISTRY_AUTHORITY` | yes | Pubkey of the authority role. |
| `JWK_REGISTRY_EMERGENCY_REVOKER` | yes | Pubkey of the emergency-revoker role. MUST be distinct from authority. |
| `JWK_REGISTRY_TIMELOCK_SECONDS` | no (default 3600) | Activation timelock for proposed JWKs and role rotations. |
| `JWK_REGISTRY_GRACE_SECONDS` | no (default 604800) | How long an entry past `valid_until_ts` stays available (devnet 7d, prod 1-3d). |
| `JWK_REGISTRY_AUTHORITY_KEYPAIR` | yes | File path to the authority keypair (private key — used to sign). |
| `JWK_REGISTRY_PAYER_KEYPAIR` | yes | File path to a SEPARATE payer keypair. The framework rejects two `Signer` slots aliased to the same account. |

## Railway deploy (production watcher)

1. New service in the existing Andromeda project, source = the same GitHub repo.
2. **Settings → Build & Deploy**:
   - Root Directory: `jwk-rotator`
   - Build Command: blank (Nixpacks auto-detects `npm install`)
   - Start Command: `npm run start`
   - Watch Paths: `jwk-rotator/**` (rebuild only on rotator changes)
3. **Settings → Networking**: do NOT generate a public domain. This is a worker, no HTTP.
4. **Variables**: minimum set —

   ```
   RPC_URL=https://api.devnet.solana.com
   JWK_REGISTRY_PROGRAM_ID=<deployed program id>
   JWK_REGISTRY_SEED=0000000000000000000000000000000000000000000000000000000000000000
   JWK_AUTHORITY_KEYPAIR_JSON=<64-byte JSON array>
   POLL_INTERVAL_SECONDS=3600
   GOOGLE_ENABLED=true
   GOOGLE_AUDIENCE=<broker client_id>
   APPLE_ENABLED=false
   ```

   Optional: `ALERT_WEBHOOK_URL`, `SUCCESSOR_WARN_DAYS`.

5. Deploy. First log line should show `[jwk-rotator] google: fetched N keys`. Subsequent lines report propose / alert events.

## Operations

The watcher proposes; **humans activate, revoke, expire**. Operational procedures (rotation, emergency revoke, expiry, role rotation) are documented in [`docs/RUNBOOK_JWK_ROTATION.md`](../docs/RUNBOOK_JWK_ROTATION.md).

Common alerts you may see:

| Alert | What it means | Action |
|---|---|---|
| `proposed new JWK ... NEEDS ACTIVATION` | New key in the provider's JWKS; watcher proposed it. | After the timelock (1h devnet), run `activate_jwk`. |
| `ACTIVE entry slot=N has a kid that is NOT in the live JWKS` (critical) | Possible key compromise OR the key aged out before grace. | Investigate; consider emergency revoke (RUNBOOK §4). |
| `ACTIVE entry expires at ... with no ACTIVE/PENDING successor` | Approaching expiry without a successor proposed. | Check the provider's JWKS for the new key; if not present yet, no action — provider will publish before expiry. |
| `RegistryFull` (critical) | All 8 slots are PENDING / ACTIVE; no recyclable slot. | Expire past-grace entries to free slots (RUNBOOK §3). |

## Safety notes

- **The authority key controls the registry.** A leak lets an attacker propose a malicious JWK (and after the timelock, activate it themselves if they keep the key). On devnet pre-alpha this is contained (data wiped at Alpha 1); for mainnet, **move the authority to a Squads M-of-N multisig** before any real funds rely on it (RUNBOOK §5).
- The watcher is single-signer by design. It cannot revoke, expire or activate — even if compromised, the worst it can do is fill the registry with PENDING entries (caps at 8 slots; ops can revoke + expire to clean up).
- `JWK_AUTHORITY_KEYPAIR_JSON` in Railway is encrypted at rest and visible only to project members. For local dev, keep `JWK_AUTHORITY_KEYPAIR` files in `.secrets/` (root `.gitignore` covers that path).
- The watcher posts a `JwkProposed` event on-chain when it successfully proposes — the audit trail is on-chain regardless of whether the alert webhook fires.

## See also

- `contracts/jwk-registry/` — the on-chain program.
- `contracts/jwk-registry/README.md` — program-level docs (account layout, instructions, design rationale).
- `docs/RUNBOOK_JWK_ROTATION.md` — operational procedures.
- `loginsocial.md` §8 — the JWK Registry chapter of the master plan.
