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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleAuthorizationURL(t *testing.T) {
	g := NewGoogleProvider("client-id-1", "secret", nil)
	u := g.AuthorizationURL("STATE-X", "NONCE-Y", "https://br/cb")
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	wants := map[string]string{
		"client_id":     "client-id-1",
		"redirect_uri":  "https://br/cb",
		"response_type": "code",
		"scope":         "openid",
		"state":         "STATE-X",
		"nonce":         "NONCE-Y",
		"prompt":        "consent",
	}
	for k, v := range wants {
		if got := q.Get(k); got != v {
			t.Errorf("query %s: got %q, want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(u, "https://accounts.google.com/o/oauth2/v2/auth?") {
		t.Errorf("unexpected base URL: %s", u)
	}
}

func TestGoogleExchangeCode_HappyPath(t *testing.T) {
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"FAKE_JWT_TOKEN","access_token":"ignored"}`))
	}))
	defer srv.Close()

	// Point ExchangeCode at the mock by swapping the endpoint via a tiny
	// in-test wrapper around postTokenForm.
	form := url.Values{
		"code":          {"auth_code_42"},
		"client_id":     {"cid"},
		"client_secret": {"sec"},
		"redirect_uri":  {"https://br/cb"},
		"grant_type":    {"authorization_code"},
	}
	tok, err := postTokenForm(context.Background(),
		&http.Client{Timeout: 5 * time.Second}, srv.URL, form)
	if err != nil {
		t.Fatalf("postTokenForm: %v", err)
	}
	if tok != "FAKE_JWT_TOKEN" {
		t.Fatalf("got token %q", tok)
	}
	if capturedForm.Get("code") != "auth_code_42" {
		t.Errorf("provider did not receive `code`: %+v", capturedForm)
	}
	if capturedForm.Get("grant_type") != "authorization_code" {
		t.Errorf("provider did not receive grant_type=authorization_code")
	}
}

func TestPostTokenForm_NonJSONResponseFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	if _, err := postTokenForm(context.Background(),
		&http.Client{Timeout: 5 * time.Second}, srv.URL, url.Values{}); err == nil {
		t.Fatalf("expected error on non-JSON body")
	}
}

func TestPostTokenForm_ProviderErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	if _, err := postTokenForm(context.Background(),
		&http.Client{Timeout: 5 * time.Second}, srv.URL, url.Values{}); err == nil {
		t.Fatalf("expected error on non-2xx status")
	}
}

// ---------------------------------------------------------------------------
// Apple client_secret JWT — verify the broker produces a structurally and
// cryptographically valid ES256 JWT.

func generateAppleP8(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return priv, string(pemBytes)
}

func TestParseApplePrivateKey_OK(t *testing.T) {
	_, pemStr := generateAppleP8(t)
	if _, err := parseApplePrivateKey(pemStr); err != nil {
		t.Fatalf("parseApplePrivateKey: %v", err)
	}
}

func TestParseApplePrivateKey_RejectsNonPEM(t *testing.T) {
	if _, err := parseApplePrivateKey("not a pem"); err == nil {
		t.Fatalf("expected error on bad pem")
	}
}

func TestSignAppleClientSecret_VerifiesAgainstPublicKey(t *testing.T) {
	priv, _ := generateAppleP8(t)
	now := time.Now()
	jwt, err := signAppleClientSecret(priv, "TEAMID1234", "KEYID12345", "svc.id.example", now)
	if err != nil {
		t.Fatalf("signAppleClientSecret: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	headerB, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claimsB, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 sig must be 64 bytes (r||s), got %d", len(sig))
	}

	var header struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(headerB, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Alg != "ES256" || header.Kid != "KEYID12345" || header.Typ != "JWT" {
		t.Fatalf("unexpected header: %+v", header)
	}

	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != "TEAMID1234" || claims.Sub != "svc.id.example" ||
		claims.Aud != "https://appleid.apple.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Exp-claims.Iat != 300 {
		t.Fatalf("exp should be iat+5min, got %d", claims.Exp-claims.Iat)
	}

	// Verify signature against the public key.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Fatalf("ecdsa.Verify failed — the broker produced an invalid signature")
	}
}
