# Andromeda Vault — Railway deployment

Single-node HashiCorp Vault running on Railway. Holds the ed25519 keys for:

- `andromeda-audit` — signs the gateway audit-log hash chain.
- `andromeda-fhe` — signs FHE decisions consumed by the `KIND_FHE_GATED` rule of the on-chain `policy-engine`.

Vault is reachable **only** via the Railway private network. There is no public ingress. Administration happens through the Railway shell.

---

## Prerequisites

- Railway CLI installed (`npm i -g @railway/cli`) and authenticated (`railway login`).
- The Andromeda Railway project already provisioned (the gateway and engines live there).
- 3 secure offline locations to store the unseal keys — e.g. 1Password, YubiKey, paper backup in a safe. **Losing the unseal keys means losing access to the audit and FHE keys forever.**

---

## Step 1 — Create the Railway service

From the project root:

```bash
# Make sure you're in the right Railway project + environment
railway link
railway environment production

# Create a new service from this Dockerfile
railway up --service andromeda-vault --detach \
  --root infra/vault
```

Or via Railway dashboard:

1. New Service → GitHub Repo → select Andromeda repo.
2. Set **Root Directory** to `infra/vault`.
3. Set **Builder** to Dockerfile.
4. **Networking**: ensure the service has a private network address. Public networking should be **disabled**.

---

## Step 2 — Attach a persistent volume

Vault Raft storage MUST live on a persistent volume. Without it, every redeploy re-initialises Vault and destroys the keys.

In Railway dashboard → andromeda-vault service → **Volumes**:

1. Add Volume.
2. Mount path: `/vault/data`.
3. Size: `1 GB` is plenty for an MVP (Raft log + 2 keys + audit log).

After attaching, redeploy so the volume is wired up.

---

## Step 3 — Initialise Vault (one-time)

Open the Railway shell for the andromeda-vault service:

```bash
railway shell --service andromeda-vault
```

Inside the shell:

```bash
export VAULT_ADDR=http://127.0.0.1:8200

# Initialise — generates 5 unseal key shares with threshold 3.
vault operator init -key-shares=5 -key-threshold=3
```

**You will see output like:**

```
Unseal Key 1: <BASE64>
Unseal Key 2: <BASE64>
Unseal Key 3: <BASE64>
Unseal Key 4: <BASE64>
Unseal Key 5: <BASE64>

Initial Root Token: hvs.<TOKEN>
```

### CRITICAL — store these IMMEDIATELY

| Item | Where it goes |
|---|---|
| **Unseal Keys 1–3** | 3 different secure offline locations (1Password vault A, 1Password vault B, paper safe). Distribute across people if multiple operators exist. |
| **Unseal Keys 4–5** | Cold backup (e.g. encrypted USB stored offsite). Used only if 3 of the 5 are lost. |
| **Initial Root Token** | 1Password (admin vault). Will be revoked once we generate scoped tokens in Step 6. |

**Do not paste any of these into Railway env vars, Slack, GitHub, or anywhere with persistent logs.** They never leave the offline storage except during a manual unseal.

---

## Step 4 — Unseal Vault (every restart)

After every Railway restart of this service, Vault boots in **sealed** state. To unseal:

```bash
railway shell --service andromeda-vault
export VAULT_ADDR=http://127.0.0.1:8200

vault operator unseal   # paste Unseal Key 1
vault operator unseal   # paste Unseal Key 2
vault operator unseal   # paste Unseal Key 3
```

After the third key, `Sealed: false` appears. The service healthcheck flips to green within 30 seconds.

**Restarts are rare events** — only when you change `vault.hcl`, redeploy, or Railway maintenance. They are NOT routine.

---

## Step 5 — Enable Transit Engine

After unsealing, log in with the root token:

```bash
vault login hvs.<ROOT_TOKEN>

# Enable the Transit secrets engine
vault secrets enable transit

# Optional but recommended: enable file audit log to /vault/data/audit.log
vault audit enable file file_path=/vault/data/audit.log
```

Continue with key creation in the next file: `KEYS_AND_TOKENS.md` (created in Etapa 3).

---

## Operational notes

- **Backup**: take a Raft snapshot before any infra change.
  ```bash
  vault operator raft snapshot save /vault/data/snapshot-$(date +%F).snap
  ```
  Download via `railway run --service andromeda-vault cat /vault/data/snapshot-...` then store offline.

- **Restart drill**: at least once before mainnet, force a restart and time the unseal procedure end-to-end. Document who runs it.

- **Token rotation**: the root token is revoked at the end of Etapa 3. Day-to-day administration uses a periodic admin token issued from a scoped policy.

- **Vault upgrade**: bump the `hashicorp/vault` tag in `Dockerfile` only after reading the upgrade notes. Snapshot first.

---

## Threat model recap

| Threat | Mitigation |
|---|---|
| Railway env-var leak | Vault tokens leak (limited blast radius — sign-only policies). Unseal keys are NOT in env vars. |
| Vault binary compromise | Snapshot + signature verification on Docker image (`hashicorp/vault` is signed). |
| Operator coercion | 3-of-5 Shamir threshold means no single operator can unseal alone (when keys are distributed). |
| Gateway compromised | Attacker gets a sign-only token. Cannot read keys, cannot rotate, cannot forge past entries. |
| Vault unreachable | Audit appends fail loud (gateway propagates error). FHE decisions error out and `/v1/confidential/sign` returns 502. Acceptable — fail-closed. |
| Volume corruption | Manual restore from latest Raft snapshot. **Take snapshots regularly.** |
