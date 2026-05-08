// HashiCorp Vault Transit Engine signer.
//
// Mirrors the Go implementation in gateway/internal/audit/signer.go so both
// services share the same operational model: ed25519 keys never leave Vault,
// every signature is locally re-verified against a configured pubkey to fail
// fast on misconfiguration, and tokens are short-lived (renewed by an
// out-of-band sidecar).
//
// Used by the FHE decision-signing route to produce signatures the on-chain
// `fhe-gated` policy template can verify against `FHEGatedPolicy.fhe_authority`.

import { verify as cryptoVerify, createPublicKey, type KeyObject } from 'node:crypto';

export interface VaultSigner {
  sign(digest: Buffer): Promise<Buffer>;
  publicKey(): Buffer;
  publicKeyBase64(): string;
}

export interface VaultTransitConfig {
  addr: string;
  token: string;
  keyName: string;
  publicKeyBase64: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

export class VaultTransitSigner implements VaultSigner {
  private readonly addr: string;
  private readonly token: string;
  private readonly keyName: string;
  private readonly pub: Buffer;
  private readonly pubKeyObject: KeyObject;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(cfg: VaultTransitConfig) {
    const addr = cfg.addr.trim().replace(/\/+$/, '');
    if (addr.length === 0) {
      throw new Error('vault addr is required');
    }
    if (!cfg.token || cfg.token.length === 0) {
      throw new Error('vault token is required');
    }
    if (!cfg.keyName || cfg.keyName.length === 0) {
      throw new Error('vault key name is required');
    }
    const pub = decodePubKey(cfg.publicKeyBase64);
    this.addr = addr;
    this.token = cfg.token;
    this.keyName = cfg.keyName;
    this.pub = pub;
    this.pubKeyObject = createEd25519PublicKey(pub);
    this.fetchImpl = cfg.fetchImpl ?? fetch;
    this.timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  publicKey(): Buffer {
    return Buffer.from(this.pub);
  }

  publicKeyBase64(): string {
    return this.pub.toString('base64');
  }

  /**
   * Sign returns the ed25519 signature over `digest`. Behaves identically to
   * Node's `crypto.sign('ed25519', digest, key)` — 64 bytes, no extra hashing,
   * matching the Go gateway's `ed25519.Sign(priv, digest)` semantics.
   *
   * Locally re-verifies the produced signature against the configured pubkey
   * before returning. A misconfigured Vault key surfaces as a thrown error
   * here rather than as an unverifiable on-chain decision.
   */
  async sign(digest: Buffer): Promise<Buffer> {
    if (!Buffer.isBuffer(digest) || digest.length === 0) {
      throw new Error('vault sign: digest must be a non-empty Buffer');
    }
    const url = `${this.addr}/v1/transit/sign/${encodeURIComponent(this.keyName)}`;
    const body = JSON.stringify({
      input: digest.toString('base64'),
      prehashed: false,
      signature_algorithm: 'ed25519',
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'X-Vault-Token': this.token,
          'Content-Type': 'application/json',
        },
        body,
        signal: controller.signal,
      });
    } catch (err: unknown) {
      throw new Error(`vault sign request failed: ${getErrorMessage(err)}`);
    } finally {
      clearTimeout(timer);
    }

    const respBody = await resp.text();
    if (resp.status < 200 || resp.status >= 300) {
      throw new Error(`vault sign non-2xx: ${resp.status} body=${respBody.slice(0, 512)}`);
    }
    let parsed: { data?: { signature?: string } };
    try {
      parsed = JSON.parse(respBody);
    } catch {
      throw new Error('vault sign: response is not valid JSON');
    }
    const wrapped = parsed.data?.signature;
    if (typeof wrapped !== 'string' || wrapped.length === 0) {
      throw new Error('vault sign: missing data.signature in response');
    }
    const parts = wrapped.split(':');
    if (parts.length !== 3 || parts[0] !== 'vault') {
      throw new Error(`vault sign: unexpected signature format ${wrapped.slice(0, 32)}...`);
    }
    let sig: Buffer;
    try {
      sig = Buffer.from(parts[2], 'base64');
    } catch (err: unknown) {
      throw new Error(`vault sign: signature base64 decode failed: ${getErrorMessage(err)}`);
    }
    if (sig.length !== ED25519_SIGNATURE_BYTES) {
      throw new Error(`vault sign: bad signature length ${sig.length}, expected ${ED25519_SIGNATURE_BYTES}`);
    }
    if (!verifyEd25519(this.pubKeyObject, digest, sig)) {
      throw new Error('vault sign: produced signature does not verify against configured pubkey');
    }
    return sig;
  }
}

/**
 * loadVaultSignerFromEnv constructs a VaultTransitSigner using the standard
 * env-var bundle. Returns null if signing is disabled (no env vars set);
 * throws if signing is partially configured.
 */
export function loadVaultSignerFromEnv(prefix: string): VaultTransitSigner | null {
  const addr = process.env[`${prefix}_VAULT_ADDR`] ?? '';
  const token = process.env[`${prefix}_VAULT_TOKEN`] ?? '';
  const keyName = process.env[`${prefix}_VAULT_KEY_NAME`] ?? '';
  const pub = process.env[`${prefix}_VAULT_PUBKEY_B64`] ?? '';

  const allEmpty = !addr && !token && !keyName && !pub;
  if (allEmpty) {
    return null;
  }
  const missing: string[] = [];
  if (!addr) missing.push(`${prefix}_VAULT_ADDR`);
  if (!token) missing.push(`${prefix}_VAULT_TOKEN`);
  if (!keyName) missing.push(`${prefix}_VAULT_KEY_NAME`);
  if (!pub) missing.push(`${prefix}_VAULT_PUBKEY_B64`);
  if (missing.length > 0) {
    throw new Error(`vault signer partially configured — missing: ${missing.join(', ')}`);
  }
  return new VaultTransitSigner({
    addr,
    token,
    keyName,
    publicKeyBase64: pub,
  });
}

function decodePubKey(b64: string): Buffer {
  if (!b64 || b64.length === 0) {
    throw new Error('vault pubkey: base64 string is required');
  }
  const raw = Buffer.from(b64, 'base64');
  if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(`vault pubkey: must be ${ED25519_PUBLIC_KEY_BYTES} bytes, got ${raw.length}`);
  }
  return raw;
}

function createEd25519PublicKey(pubkey: Buffer): KeyObject {
  // Node's KeyObject API expects an ed25519 SubjectPublicKeyInfo DER. The
  // raw 32-byte pubkey is wrapped with the standard ed25519 OID prefix.
  const ED25519_SPKI_PREFIX = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, pubkey]);
  const keyObject = createPublicKey({
    key: spki,
    format: 'der',
    type: 'spki',
  });
  return keyObject;
}

function verifyEd25519(keyObject: KeyObject, message: Buffer, signature: Buffer): boolean {
  // For ed25519 (and ed448), Node's verify accepts a null algorithm.
  return cryptoVerify(null, message, keyObject, signature);
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return 'unknown error';
}
