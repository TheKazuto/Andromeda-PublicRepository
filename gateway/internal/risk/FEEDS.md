# Risk Blocklist Feeds

This document lists open-source blocklist feeds for ingestion into the Andromeda risk layer.

## Recommended Feeds (Phase F-RISK-2)

### 1. MetaMask Phishing Detection List (Primary)

**URL:** https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json  
**Format:** JSON with `blacklist` array of Ethereum addresses  
**License:** Apache 2.0 (FOSS)  
**Cadence:** Updated on commit (typically daily)  
**Maintenance:** Active (MetaMask project)  
**Category:** phishing  
**Parsing:** Extract `blacklist` array only (ignore `whitelist`)

**Rationale:** MetaMask's phishing detector is widely used and trusted. High signal-to-noise ratio due to MetaMask's strong curation process. Covers EVM phishing addresses.

**Risk Assessment:**
- Actively maintained: ✅ Yes (updated with each phishing campaign)
- License compatible: ✅ Yes (Apache 2.0)
- False positive rate: Low
- Coverage: High for EVM chains

**Configuration:** 
```
https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json|metamask-phishing|phishing|Apache-2.0
```

---

### 2. OpenChain Verified Scam Addresses (Secondary)

**URL:** https://api.openchain.xyz/v1/addresses?chainId=1  
**Format:** JSON with verified scam addresses  
**License:** MIT (FOSS)  
**Cadence:** Real-time / Updated continuously  
**Maintenance:** Active (OpenChain project)  
**Category:** scam, drainer  
**Parsing:** Extract address array from response, parse by chain

**Rationale:** OpenChain provides verified scam addresses including token drainers, fake bridges, and approval scams. Lower false positive rate due to verification process.

**Risk Assessment:**
- Actively maintained: ✅ Yes (real-time updates)
- License compatible: ✅ Yes (MIT)
- False positive rate: Very low (verified by community)
- Coverage: Multi-chain (EVM + others)

**Configuration:**
```
https://api.openchain.xyz/v1/addresses?chainId=1|openchain-ethereum-scams|scam|MIT
```

---

## Configuration Format

Feeds are specified in `RISK_BLOCKLIST_FEEDS` environment variable (comma-separated list):

```
https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json|metamask-phishing|phishing|Apache-2.0,https://api.openchain.xyz/v1/addresses?chainId=1|openchain-ethereum-scams|scam|MIT
```

Format per feed: `URL|SOURCE|CATEGORY|LICENSE`
- `URL`: Full feed URL (can contain `://` without parsing conflicts)
- `SOURCE`: Feed identifier (e.g., "metamask-phishing")
- `CATEGORY`: Risk category (e.g., "phishing", "scam", "drainer")
- `LICENSE`: SPDX license identifier or free-text license name

---

## Initial Deployment (Phase F-RISK-2)

Start with feeds #1 (MetaMask) and optionally #2 (OpenChain):
1. MetaMask Phishing List (high signal, widely trusted)
2. OpenChain Verified Scams (low FP, multi-chain coverage)

---

## Integration Details

### Leader Election
- Only one gateway replica ingests feeds at a time (Postgres advisory lock, LockID `0x416E64726F6706`)
- Other replicas wait for leader election; on leader failure, another replica claims the lock within ~30 seconds

### Download Strategy
- Each feed is downloaded on the schedule set by `RISK_INGEST_TICK_SECONDS` (default 3600s / 1 hour)
- Leader election ensures exactly one concurrent download per feed
- Circuit breaker stops retries after 3+ consecutive failures (recovers after 60s of half-open state)
- HTTP client rejects redirects (SSRF protection)
- Size limit: 25 MB per feed (prevents OOM from malicious feeds)
- Timeout: 30 seconds per feed (configurable via `RISK_INGEST_TIMEOUT_SEC`)

### Failure Handling
- Download failure: logs error, updates `last_error_at` + `last_error_msg`, skips parsing
- Variation guard: if entry count changes by >30%, skips update (detect feed poisoning)
- State preservation: `entries_upserted` baseline is never zeroed on error (M2 safety)
- Backoff: overdue feeds are retried on next tick (tunable via `RISK_INGEST_TICK_SECONDS`)

### Address Normalization (H7)
All addresses normalized via `NormalizeAddress()`:
- EVM hex addresses: lowercase + remove 0x prefix
- Other formats (base58, etc.): preserve case (per store contract)
- Empty/invalid: skipped silently

### Audit Trail
Each entry records:
- `destination`: Normalized address (primary key)
- `source`: Feed name (e.g., "metamask-phishing")
- `category`: Risk category (e.g., "phishing", "scam")
- `license`: Feed license for audit
- `fetched_at`: Ingestion timestamp
- `content_hash`: SHA256 hash of feed content (dedup guard)

---

## Notes on Excluded Feeds

**web3antivirus.info**: Removed from recommendations due to:
- Non-SPDX license (ambiguous "community" license)
- Single-vendor supply chain (higher risk of manipulation)
- Overlapping coverage with MetaMask (better signal-to-noise in MetaMask)

---

## Future Enhancements

- **Multi-chain address parsers** (Solana base58, Cosmos bech32, Bitcoin legacy/segwit)
- **Confidence scoring** (low/medium/high) per entry — currently all entries are binary
- **Per-tenant allowlists** to override blocks (not included in F-RISK-2)
- **Forta Network** (https://forta.org) — Real-time threat detection via validators (API TBD)
- **Custom tenant blocklists** — Allow tenants to upload/manage lists per-tenant (future)

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-22 | Remove web3antivirus | Non-SPDX license, single-vendor risk |
| 2026-05-22 | Pipe separator (`\|`) for config | Avoid collision with `https://` scheme in URL parsing |
| 2026-05-22 | 25 MB size limit | Conservative MVP; MetaMask + OpenChain ~100 KB each |
| 2026-05-22 | No severity/confidence in MVP | Job populates blocklist only; risk score is RT2 responsibility |
