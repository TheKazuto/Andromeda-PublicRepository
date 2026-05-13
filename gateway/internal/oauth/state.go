// Package oauth implements the Login Social OAuth broker (loginsocial.md §5.4
// item 1). The broker is a server-side intermediary that hosts Andromeda's
// global OAuth client, handshakes with Google/Apple using `scope=openid`,
// and returns the resulting id_token to the tenant app via Authorization
// Code + PKCE. The broker never custodies any key and never stores user
// identity data beyond the short-lived state cookie + one-time code↔id_token
// mapping in Redis.
//
// This file contains the HMAC-signed state cookie used to thread the
// in-flight OAuth handshake from /authorize through the provider redirect
// back to /callback without any server-side session storage.
package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StateCookieName is the cookie that carries the signed OAuth state across
// the provider redirect. The `__Host-` prefix forces the browser to require
// Secure + path=/ + no Domain attribute, which is the strictest cookie
// scope available.
const StateCookieName = "__Host-andromeda-oauth-state"

// StateCookieTTL bounds how long an in-flight OAuth handshake can live. A
// user that abandons the consent screen will simply hit an expired-state
// error on return — they restart from /authorize. 10 minutes is generous
// enough for slow consent flows and short enough to limit replay windows.
const StateCookieTTL = 10 * time.Minute

// StateClaims is the data the broker keeps for the duration of one OAuth
// handshake. Everything the broker needs after the provider redirect lives
// here — there is no server-side session.
type StateClaims struct {
	// TenantID is the gateway tenant (users.id) that started the handshake.
	// Used for audit + as the lookup key for tenant_oauth_redirects.
	TenantID string `json:"t"`

	// Provider selected at /authorize (google or apple).
	Provider string `json:"p"`

	// RedirectURI the tenant app wants the short-code delivered to. Must
	// have already passed the tenant_oauth_redirects allowlist check
	// before being placed in the state cookie.
	RedirectURI string `json:"r"`

	// AppState is the opaque value the tenant app passed to /authorize.
	// The broker echoes it back to the tenant app verbatim. Used for
	// CSRF protection on the tenant app's own redirect.
	AppState string `json:"as"`

	// CodeChallenge is the PKCE S256 challenge bound to this handshake.
	// The broker stores it next to the short_code in Redis; the tenant
	// app proves possession of the matching verifier at token-exchange.
	CodeChallenge string `json:"cc"`

	// Nonce is the oidc_nonce the app already obtained from
	// POST /v1/oidc/nonce. The broker forwards it to the provider so the
	// returned id_token includes it as a claim. The broker does NOT
	// recompute or replace it.
	Nonce string `json:"n"`

	// IssuedAt is the unix timestamp when the cookie was minted. Used to
	// enforce StateCookieTTL on the callback side. We don't trust the
	// browser's clock — we check against the server's now.
	IssuedAt int64 `json:"iat"`

	// CSRF is a 16-byte random nonce that the /callback hands back as
	// a hidden field. Combined with the cookie being HttpOnly+SameSite,
	// this defeats any cross-site forgery of /callback.
	CSRF string `json:"x"`
}

// errInvalidState is the only error /callback surfaces to the user; the
// real reason lives in the audit log. Distinguishing "expired" from "bad
// signature" would give an attacker a probe.
var errInvalidState = errors.New("invalid or expired OAuth state")

// SignState encodes claims into a `payload.signature` cookie value. The
// payload is base64url(JSON(claims)) and the signature is base64url of
// HMAC-SHA256 over the payload bytes.
func SignState(secret []byte, claims StateClaims) (string, error) {
	if len(secret) < 32 {
		return "", fmt.Errorf("oauth.SignState: secret must be at least 32 bytes")
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oauth.SignState: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

// VerifyState decodes and validates a cookie value produced by SignState.
// Constant-time signature comparison; bounded payload size.
func VerifyState(secret []byte, raw string, now time.Time) (StateClaims, error) {
	var zero StateClaims
	if len(secret) < 32 {
		return zero, fmt.Errorf("oauth.VerifyState: secret must be at least 32 bytes")
	}
	// Reject obviously oversized cookies before any base64/JSON work. The
	// signed payload is tiny — a megabyte cookie is hostile.
	if len(raw) == 0 || len(raw) > 4096 {
		return zero, errInvalidState
	}
	dot := strings.IndexByte(raw, '.')
	if dot <= 0 || dot == len(raw)-1 {
		return zero, errInvalidState
	}
	payload, sigB64 := raw[:dot], raw[dot+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return zero, errInvalidState
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return zero, errInvalidState
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return zero, errInvalidState
	}
	var claims StateClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return zero, errInvalidState
	}
	if claims.IssuedAt <= 0 {
		return zero, errInvalidState
	}
	age := now.Unix() - claims.IssuedAt
	if age < -60 || age > int64(StateCookieTTL.Seconds()) {
		// `-60` tolerates a 1-minute clock skew between the gateway
		// pod that minted the cookie and the one that verifies it.
		return zero, errInvalidState
	}
	return claims, nil
}

// WriteStateCookie sets the signed state cookie on `w`. The `__Host-` prefix
// is enforced by the browser (Secure, no Domain, Path=/).
func WriteStateCookie(w http.ResponseWriter, value string, isProduction bool) {
	cookie := &http.Cookie{
		Name:     StateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		// In dev (http://localhost) Secure must be false or the browser
		// drops the cookie silently. In production it is always true.
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode, // Lax so the cookie survives the provider 302
		MaxAge:   int(StateCookieTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

// ClearStateCookie removes the cookie. Called from /callback once the
// handshake completes (success or failure).
func ClearStateCookie(w http.ResponseWriter, isProduction bool) {
	cookie := &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

// ErrInvalidState is the public sentinel for /callback to surface.
var ErrInvalidState = errInvalidState
