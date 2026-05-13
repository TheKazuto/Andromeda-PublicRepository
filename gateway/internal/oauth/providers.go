// OAuth provider adapters for the Login Social broker.
//
// Two concrete providers — Google and Apple — implement a tiny common
// interface that the /authorize and /callback handlers use without caring
// which one is on the other side. The authoritative validation of the
// id_token still lives on-chain (oidc-verifier) plus the off-chain
// /v1/oidc/validate pre-check; this layer only fetches the id_token from
// the provider's token endpoint and hands it to the caller.

package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProviderName enumerates the providers the broker can handshake with.
type ProviderName string

const (
	ProviderGoogle ProviderName = "google"
	ProviderApple  ProviderName = "apple"
)

// Provider is what /authorize and /callback talk to. Implementations are
// stateless past initial construction.
type Provider interface {
	// Name returns the provider key used in URLs and audit events.
	Name() ProviderName

	// AuthorizationURL builds the URL the browser is redirected to in
	// /authorize. `state` is the signed cookie value; `nonce` is the
	// oidc_nonce the app already obtained from /v1/oidc/nonce.
	AuthorizationURL(state, nonce, redirectURI string) string

	// ExchangeCode swaps the provider's authorization code for an
	// id_token. `redirectURI` MUST be the exact same value the browser
	// hit /authorize with — Google/Apple bind the code to that URI.
	ExchangeCode(ctx context.Context, code, redirectURI string) (idToken string, err error)
}

// --- Google ---------------------------------------------------------------

// GoogleProvider implements Provider against accounts.google.com.
type GoogleProvider struct {
	ClientID     string
	ClientSecret string
	client       *http.Client
}

// NewGoogleProvider returns a Provider bound to the given Google OAuth client.
// `httpClient` is optional; nil defaults to http.DefaultClient with a 10s
// timeout (Google's token endpoint is reliably fast).
func NewGoogleProvider(clientID, clientSecret string, httpClient *http.Client) *GoogleProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &GoogleProvider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		client:       httpClient,
	}
}

func (g *GoogleProvider) Name() ProviderName { return ProviderGoogle }

func (g *GoogleProvider) AuthorizationURL(state, nonce, redirectURI string) string {
	q := url.Values{
		"client_id":     {g.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {state},
		"nonce":         {nonce},
		// Force re-consent so a previously-granted broader scope cannot
		// silently come back; we only want openid.
		"prompt": {"consent"},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode()
}

func (g *GoogleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	return postTokenForm(ctx, g.client, "https://oauth2.googleapis.com/token", form)
}

// --- Apple ---------------------------------------------------------------

// AppleProvider implements Provider against appleid.apple.com. Apple's
// client_secret is itself a short-lived JWT (ES256) signed with the
// .p8 key from the Apple Developer console — see signAppleClientSecret.
type AppleProvider struct {
	ServiceID  string // OAuth client_id
	TeamID     string
	KeyID      string
	privateKey *ecdsa.PrivateKey
	client     *http.Client
}

// NewAppleProvider parses the PEM (PKCS#8) private key from the Apple
// Developer console and returns the configured provider. Returns an error
// if the PEM is malformed or not a P-256 ECDSA key.
func NewAppleProvider(serviceID, teamID, keyID, privateKeyPEM string, httpClient *http.Client) (*AppleProvider, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	priv, err := parseApplePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("oauth.NewAppleProvider: parse private key: %w", err)
	}
	return &AppleProvider{
		ServiceID:  serviceID,
		TeamID:     teamID,
		KeyID:      keyID,
		privateKey: priv,
		client:     httpClient,
	}, nil
}

func (a *AppleProvider) Name() ProviderName { return ProviderApple }

func (a *AppleProvider) AuthorizationURL(state, nonce, redirectURI string) string {
	q := url.Values{
		"client_id":     {a.ServiceID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"response_mode": {"query"}, // default is form_post for `scope` requests; we want a 302 GET
		"scope":         {"openid"},
		"state":         {state},
		"nonce":         {nonce},
	}
	return "https://appleid.apple.com/auth/authorize?" + q.Encode()
}

func (a *AppleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	secret, err := signAppleClientSecret(a.privateKey, a.TeamID, a.KeyID, a.ServiceID, time.Now())
	if err != nil {
		return "", fmt.Errorf("oauth: sign apple client_secret: %w", err)
	}
	form := url.Values{
		"code":          {code},
		"client_id":     {a.ServiceID},
		"client_secret": {secret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	return postTokenForm(ctx, a.client, "https://appleid.apple.com/auth/token", form)
}

// --- shared helpers -------------------------------------------------------

// postTokenForm POSTs a urlencoded form to the provider's `/token` endpoint
// and returns the `id_token` field from the JSON response.
func postTokenForm(ctx context.Context, c *http.Client, endpoint string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("post token endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Cap the body — a hostile/buggy provider response should not OOM us.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		// Don't surface the provider's raw error to the client — log it
		// and return a generic. Body capped above so this is safe.
		return "", fmt.Errorf("provider token endpoint returned status %d", resp.StatusCode)
	}
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if out.Error != "" || out.IDToken == "" {
		return "", errors.New("provider token endpoint did not return an id_token")
	}
	return out.IDToken, nil
}

// --- Apple client_secret signer ------------------------------------------

// parseApplePrivateKey extracts the *ecdsa.PrivateKey from an Apple .p8 PEM
// (PKCS#8). Returns an error if the PEM is malformed or the key is not on
// P-256.
func parseApplePrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8 parse: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA (got %T)", parsed)
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("Apple .p8 must be ECDSA P-256")
	}
	return priv, nil
}

// signAppleClientSecret builds the ES256 JWT Apple requires as the
// `client_secret` at the /token endpoint. Apple's spec: alg=ES256, header
// has `kid`, claims set has `iss=<team_id>, iat=now, exp<=now+15777000s (6mo),
// aud=https://appleid.apple.com, sub=<service_id>`. The broker mints a
// 5-minute JWT every call — short-lived secrets are cheap and avoid having
// to cache/rotate them.
func signAppleClientSecret(priv *ecdsa.PrivateKey, teamID, keyID, serviceID string, now time.Time) (string, error) {
	header := map[string]string{"alg": "ES256", "kid": keyID, "typ": "JWT"}
	claims := map[string]any{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": serviceID,
	}
	headerB, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsB, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerB) + "." +
		base64.RawURLEncoding.EncodeToString(claimsB)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}
	// JWS ES256 signature is the fixed-size IEEE P1363 form: r || s, each
	// padded to 32 bytes — NOT the ASN.1 sequence ecdsa.Sign-on-Go-stdlib
	// is designed for. Pad explicitly.
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), nil
}
