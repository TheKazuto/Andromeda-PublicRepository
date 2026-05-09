package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Signer is the abstraction the Recorder uses to produce ed25519 signatures.
// The default implementation keeps the key in process memory; production
// deployments inject a KMS-backed implementation that never exposes the key
// material to the application.
type Signer interface {
	// Sign returns the ed25519 signature over `digest`. Implementations MUST
	// behave identically to ed25519.Sign — i.e. a 64-byte signature over the
	// raw bytes (no extra hashing).
	Sign(ctx context.Context, digest []byte) ([]byte, error)

	// PublicKey returns the verification key. Stable for the lifetime of the
	// signer — rotation requires a new Signer instance plus migration of the
	// chain head.
	PublicKey() ed25519.PublicKey
}

// EnvSigner keeps the ed25519 private key in memory. Suitable for local
// development and pre-alpha. NOT for production — see docs/AUDIT_KMS.md.
type EnvSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewEnvSigner returns a Signer that uses the supplied private key (or a
// freshly-generated transient one if `privateKeyB64` is empty). Returns an
// error if the supplied key cannot be decoded.
func NewEnvSigner(privateKeyB64 string) (*EnvSigner, bool, error) {
	if privateKeyB64 == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("env signer keygen: %w", err)
		}
		return &EnvSigner{priv: priv, pub: pub}, true, nil
	}
	raw, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, false, fmt.Errorf("decode env signer key: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		priv := ed25519.PrivateKey(raw)
		return &EnvSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, false, nil
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(raw)
		return &EnvSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, false, nil
	default:
		return nil, false, fmt.Errorf("env signer key must be 32 (seed) or 64 (private) bytes, got %d", len(raw))
	}
}

// Sign implements Signer.
func (e *EnvSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return ed25519.Sign(e.priv, digest), nil
}

// PublicKey implements Signer.
func (e *EnvSigner) PublicKey() ed25519.PublicKey { return e.pub }

// VaultTransitSigner is a HashiCorp Vault Transit Engine backend. Vault is
// chosen as the canonical KMS for ed25519 because the major cloud KMS offerings
// don't all support ed25519 (AWS KMS does not as of 2026; GCP KMS does, Azure
// Key Vault does not).
//
// Configuration (env vars on the gateway):
//   - ANDROMEDA_AUDIT_SIGNER=vault
//   - ANDROMEDA_AUDIT_VAULT_ADDR=https://vault.example.internal
//   - ANDROMEDA_AUDIT_VAULT_TOKEN=<short-lived token, rotated by sidecar>
//   - ANDROMEDA_AUDIT_VAULT_KEY_NAME=andromeda-audit
//
// Vault setup (one-time, by an operator):
//   vault secrets enable transit
//   vault write -f transit/keys/andromeda-audit type=ed25519
//   vault read -format=json transit/keys/andromeda-audit | jq -r '.data.keys."1".public_key'
//
// The public_key is base64-encoded raw 32 bytes — copy it into
// ANDROMEDA_AUDIT_VAULT_PUBKEY_B64 so the gateway boots without a network
// round-trip.
type VaultTransitSigner struct {
	addr     string
	token    string
	keyName  string
	pub      ed25519.PublicKey
	httpDoer interface {
		Do(req *http.Request) (*http.Response, error)
	}
}

// VaultConfig is the typed surface for the env-var bundle.
type VaultConfig struct {
	Addr      string
	Token     string
	KeyName   string
	PubKeyB64 string
	HTTPDoer  interface {
		Do(req *http.Request) (*http.Response, error)
	}
}

// NewVaultTransitSigner constructs a Signer backed by Vault Transit. The public
// key MUST be supplied so we can verify the signer locally without a Vault
// round-trip on boot.
func NewVaultTransitSigner(cfg VaultConfig) (*VaultTransitSigner, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.Addr), "/")
	if addr == "" {
		return nil, fmt.Errorf("vault addr is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault token is required")
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("vault key name is required")
	}
	pub, err := decodePubKeyB64(cfg.PubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("vault pubkey: %w", err)
	}
	doer := cfg.HTTPDoer
	if doer == nil {
		doer = &http.Client{Timeout: 10 * time.Second}
	}
	return &VaultTransitSigner{
		addr:     addr,
		token:    cfg.Token,
		keyName:  cfg.KeyName,
		pub:      pub,
		httpDoer: doer,
	}, nil
}

// Sign POSTs to /v1/transit/sign/<key>. Vault returns
// `vault:v<n>:<base64sig>`; we strip the prefix and decode.
func (v *VaultTransitSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"input":            base64.StdEncoding.EncodeToString(digest),
		"prehashed":        false,
		"signature_algorithm": "ed25519",
	})
	if err != nil {
		return nil, fmt.Errorf("vault sign marshal: %w", err)
	}
	url := v.addr + "/v1/transit/sign/" + v.keyName
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpDoer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault sign request: %s", redactVaultToken(err.Error()))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault sign non-2xx: %d body=%s", resp.StatusCode, redactVaultToken(string(respBody)))
	}
	var parsed struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("vault sign decode: %w", err)
	}
	parts := strings.SplitN(parsed.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("vault sign: unexpected format %q", parsed.Data.Signature)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault sign decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("vault sign: bad signature length %d", len(sig))
	}
	// Defensive — verify locally so a misconfigured Vault key surfaces
	// immediately rather than producing an unverifiable audit log.
	if !ed25519.Verify(v.pub, digest, sig) {
		return nil, fmt.Errorf("vault sign: produced signature does not verify against configured pubkey")
	}
	return sig, nil
}

// PublicKey implements Signer.
func (v *VaultTransitSigner) PublicKey() ed25519.PublicKey { return v.pub }

// redactVaultToken strips Vault token artefacts from arbitrary strings used
// in error returns. Vault tokens (server-issued) start with `hvs.`, recovery
// tokens with `hvr.`, and root tokens may start with `hvb.` or `hsv.` —
// scrub them all to be safe. Operators tracing failures can correlate via
// log correlation IDs without ever seeing the raw secret.
func redactVaultToken(s string) string {
	prefixes := []string{"hvs.", "hvr.", "hvb.", "hsv.", "s."}
	out := s
	for _, p := range prefixes {
		for {
			i := strings.Index(out, p)
			if i < 0 {
				break
			}
			end := i + len(p)
			for end < len(out) {
				c := out[end]
				if (c >= 'a' && c <= 'z') ||
					(c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') ||
					c == '-' || c == '_' || c == '.' {
					end++
					continue
				}
				break
			}
			out = out[:i] + "[REDACTED]" + out[end:]
		}
	}
	return out
}

func decodePubKeyB64(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("public key is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
