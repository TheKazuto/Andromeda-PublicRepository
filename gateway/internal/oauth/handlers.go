// HTTP handlers for the Login Social OAuth broker.
//
//   GET  /v1/oauth/authorize       — browser starts here, 302 to provider
//   GET  /v1/oauth/callback        — provider redirects here, code → id_token
//   POST /v1/oauth/token-exchange  — tenant app fetches id_token via PKCE
//
// Authorize/callback are browser flows (no X-Api-Key on the callback redirect
// from the provider; the X-Api-Key is enforced on /authorize so we know which
// tenant initiated the handshake). Token-exchange is a server-side call from
// the tenant app and requires X-Api-Key.
//
// All three handlers are deliberately thin: parsing, validation, audit. The
// signing-input-binding (state cookie HMAC), the Redis code↔id_token map,
// and the per-provider token-endpoint dance live in state.go / store.go /
// providers.go.

package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RedirectAllowlist resolves the per-tenant allowlist of redirect URIs. Each
// row in `tenant_oauth_redirects` is one (user_id, redirect_uri) pair; the
// /authorize handler rejects any request whose redirect_uri does not appear.
type RedirectAllowlist interface {
	IsAllowed(ctx context.Context, userID, redirectURI string) (bool, error)
}

// AuditAppender lets handlers record audit events without depending on the
// concrete audit.Recorder. Implementations live in the api package.
type AuditAppender interface {
	Append(ctx context.Context, ev AuditEvent) error
}

// AuditEvent is the broker-local event the handlers emit. The api package
// translates it into the canonical audit envelope.
type AuditEvent struct {
	TenantID  string
	APIKeyID  string
	EventType string
	Provider  string
	Outcome   string // "started" | "completed" | "rejected"
	Reason    string // short non-sensitive tag; never the id_token / sub
}

// TenantInfo carries the bits the handlers need from the authenticated
// X-Api-Key — populated by the caller-supplied AuthFromRequest.
type TenantInfo struct {
	UserID   string
	APIKeyID string
}

// HandlerOptions wires the handlers to the rest of the gateway.
type HandlerOptions struct {
	BaseURL         string // OAuthBrokerConfig.BaseURL
	StateHMACSecret []byte // OAuthBrokerConfig.StateHMACSecret
	IsProduction    bool   // cfg.IsProduction()
	Providers       map[ProviderName]Provider
	Store           *Store
	Allowlist       RedirectAllowlist
	Audit           AuditAppender
	Logger          *slog.Logger
	AuthFromRequest func(*http.Request) (TenantInfo, bool)
}

// Handler bundles the three routes behind helpers that share the same opts.
type Handler struct{ opts HandlerOptions }

// NewHandler validates the options and returns a configured Handler.
func NewHandler(opts HandlerOptions) (*Handler, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("oauth.NewHandler: BaseURL is required")
	}
	if len(opts.StateHMACSecret) < 32 {
		return nil, fmt.Errorf("oauth.NewHandler: StateHMACSecret must be at least 32 bytes")
	}
	if len(opts.Providers) == 0 {
		return nil, fmt.Errorf("oauth.NewHandler: at least one provider must be registered")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("oauth.NewHandler: code Store is required")
	}
	if opts.Allowlist == nil {
		return nil, fmt.Errorf("oauth.NewHandler: RedirectAllowlist is required")
	}
	if opts.AuthFromRequest == nil {
		return nil, fmt.Errorf("oauth.NewHandler: AuthFromRequest is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Handler{opts: opts}, nil
}

// callbackURI is what we register with the OAuth provider and what we send
// it on every /authorize. Bound to a constant path so a rotation of
// BaseURL does not orphan registered URIs.
func (h *Handler) callbackURI() string { return h.opts.BaseURL + "/v1/oauth/callback" }

// nonceRe is the same regex enforced by the on-chain verifier and the
// `/v1/oidc/validate` route — a 43-char base64url string (no padding).
var nonceRe = mustCompile(`^[A-Za-z0-9_-]{43}$`)

// codeChallengeRe matches a PKCE S256 challenge: 43 chars base64url.
var codeChallengeRe = mustCompile(`^[A-Za-z0-9_-]{43}$`)

func (h *Handler) audit(ctx context.Context, ev AuditEvent) {
	if h.opts.Audit == nil {
		return
	}
	if err := h.opts.Audit.Append(ctx, ev); err != nil {
		h.opts.Logger.Warn("oauth audit append failed", "err", err, "event", ev.EventType)
	}
}

// --- GET /v1/oauth/authorize ---------------------------------------------

// Authorize handler. The browser arrives with:
//
//	provider=google|apple
//	redirect_uri        — exact match against tenant_oauth_redirects
//	app_state           — opaque, echoed back to tenant app on success
//	code_challenge      — PKCE S256 challenge (base64url, 43 chars)
//	code_challenge_method=S256
//	nonce               — the oidc_nonce already obtained from /v1/oidc/nonce
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.opts.AuthFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	q := r.URL.Query()
	providerName := ProviderName(strings.ToLower(strings.TrimSpace(q.Get("provider"))))
	prov, providerOk := h.opts.Providers[providerName]
	if !providerOk {
		writeError(w, http.StatusBadRequest, "unsupported provider")
		return
	}
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	if !isHTTPSOrLocal(redirectURI) {
		writeError(w, http.StatusBadRequest, "redirect_uri must be https:// (or http://localhost in development)")
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		writeError(w, http.StatusBadRequest, "code_challenge_method must be S256")
		return
	}
	codeChallenge := q.Get("code_challenge")
	if !codeChallengeRe.MatchString(codeChallenge) {
		writeError(w, http.StatusBadRequest, "code_challenge must be 43-char base64url")
		return
	}
	nonce := q.Get("nonce")
	if !nonceRe.MatchString(nonce) {
		writeError(w, http.StatusBadRequest, "nonce must be 43-char base64url (the oidc_nonce from /v1/oidc/nonce)")
		return
	}
	appState := q.Get("app_state")
	if len(appState) > 256 {
		writeError(w, http.StatusBadRequest, "app_state must be <= 256 chars")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	allowed, err := h.opts.Allowlist.IsAllowed(ctx, tenant.UserID, redirectURI)
	if err != nil {
		h.opts.Logger.Error("oauth: redirect allowlist lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !allowed {
		h.audit(r.Context(), AuditEvent{
			TenantID: tenant.UserID, APIKeyID: tenant.APIKeyID,
			EventType: "oauth.handshake.rejected", Provider: string(providerName),
			Outcome: "rejected", Reason: "redirect_not_allowed",
		})
		writeError(w, http.StatusForbidden, "redirect_uri is not on this tenant's allowlist")
		return
	}

	claims := StateClaims{
		TenantID:      tenant.UserID,
		Provider:      string(providerName),
		RedirectURI:   redirectURI,
		AppState:      appState,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		IssuedAt:      time.Now().Unix(),
	}
	cookie, err := SignState(h.opts.StateHMACSecret, claims)
	if err != nil {
		h.opts.Logger.Error("oauth: sign state cookie failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	WriteStateCookie(w, cookie, h.opts.IsProduction)

	authURL := prov.AuthorizationURL(cookie, nonce, h.callbackURI())
	h.audit(r.Context(), AuditEvent{
		TenantID: tenant.UserID, APIKeyID: tenant.APIKeyID,
		EventType: "oauth.handshake.started", Provider: string(providerName),
		Outcome: "started",
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// --- GET /v1/oauth/callback ----------------------------------------------

// Callback handler. The provider redirects the browser back here with
// `?code=…&state=…`. We:
//  1. Verify the state cookie + that the query echo matches it.
//  2. Exchange the provider's code for an id_token (server-side).
//  3. Mint a 32-byte short_code, store {short_code → {id_token, pkce}} in Redis.
//  4. Redirect the browser to the tenant's redirect_uri with the short_code.
//
// We never log the id_token. The cookie is cleared on the way out.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	cookieVal, err := readStateCookie(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing OAuth state cookie")
		return
	}
	claims, err := VerifyState(h.opts.StateHMACSecret, cookieVal, time.Now())
	if err != nil {
		ClearStateCookie(w, h.opts.IsProduction)
		writeError(w, http.StatusBadRequest, "invalid OAuth state")
		return
	}
	echo := r.URL.Query().Get("state")
	// constant-time string compare — `state` from the URL is attacker-controlled
	if subtle.ConstantTimeCompare([]byte(echo), []byte(cookieVal)) != 1 {
		ClearStateCookie(w, h.opts.IsProduction)
		writeError(w, http.StatusBadRequest, "OAuth state mismatch")
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Provider reported a failure (user denied consent, etc).
		ClearStateCookie(w, h.opts.IsProduction)
		h.audit(r.Context(), AuditEvent{
			TenantID:  claims.TenantID,
			EventType: "oauth.handshake.completed", Provider: claims.Provider,
			Outcome: "rejected", Reason: "provider_error_" + errParam,
		})
		// Redirect anyway with the error so the app can act — the tenant
		// app's redirect_uri must be prepared for `?error=...`.
		u, _ := url.Parse(claims.RedirectURI)
		qv := u.Query()
		qv.Set("error", errParam)
		qv.Set("state", claims.AppState)
		u.RawQuery = qv.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	providerCode := strings.TrimSpace(r.URL.Query().Get("code"))
	if providerCode == "" {
		ClearStateCookie(w, h.opts.IsProduction)
		writeError(w, http.StatusBadRequest, "missing provider code")
		return
	}
	prov, ok := h.opts.Providers[ProviderName(claims.Provider)]
	if !ok {
		ClearStateCookie(w, h.opts.IsProduction)
		writeError(w, http.StatusBadRequest, "unknown provider in state")
		return
	}

	exchangeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	idToken, err := prov.ExchangeCode(exchangeCtx, providerCode, h.callbackURI())
	if err != nil {
		ClearStateCookie(w, h.opts.IsProduction)
		h.opts.Logger.Warn("oauth: exchange code failed", "provider", claims.Provider, "err", err)
		h.audit(r.Context(), AuditEvent{
			TenantID:  claims.TenantID,
			EventType: "oauth.handshake.completed", Provider: claims.Provider,
			Outcome: "rejected", Reason: "provider_exchange_failed",
		})
		writeError(w, http.StatusBadGateway, "OAuth code exchange failed")
		return
	}
	shortCode := randomURLSafe(32)
	entry := Entry{
		IDToken:       idToken,
		Provider:      claims.Provider,
		CodeChallenge: claims.CodeChallenge,
		TenantID:      claims.TenantID,
	}
	putCtx, cancel2 := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel2()
	if err := h.opts.Store.Put(putCtx, shortCode, entry); err != nil {
		ClearStateCookie(w, h.opts.IsProduction)
		h.opts.Logger.Error("oauth: put short code failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ClearStateCookie(w, h.opts.IsProduction)

	u, err := url.Parse(claims.RedirectURI)
	if err != nil {
		// Should not happen — we validated the URI at /authorize. Defensive.
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	qv := u.Query()
	qv.Set("code", shortCode)
	qv.Set("state", claims.AppState)
	u.RawQuery = qv.Encode()

	h.audit(r.Context(), AuditEvent{
		TenantID:  claims.TenantID,
		EventType: "oauth.handshake.completed", Provider: claims.Provider,
		Outcome: "completed",
	})
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// --- POST /v1/oauth/token-exchange ---------------------------------------

type tokenExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type tokenExchangeResponse struct {
	IDToken  string `json:"id_token"`
	Provider string `json:"provider"`
}

// TokenExchange handler. The tenant app POSTs with X-Api-Key:
//
//	{ "code": "<short_code from /callback>", "code_verifier": "<PKCE verifier>" }
//
// We verify PKCE, atomically take-and-delete the entry from Redis, and return
// the id_token. A code can be redeemed at most once.
func (h *Handler) TokenExchange(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.opts.AuthFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	if r.Header.Get("Content-Type") == "" ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var body tokenExchangeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// PKCE verifier per RFC 7636 §4.1: 43..128 chars from the unreserved
	// set [A-Za-z0-9-._~]. We accept 43..128 base64url for simplicity (which
	// is a subset of the spec — the standard verifier S256 sha256s and
	// base64urls the bytes, so this matches what real clients produce).
	if len(body.Code) < 32 || len(body.Code) > 128 ||
		len(body.CodeVerifier) < 43 || len(body.CodeVerifier) > 128 {
		writeError(w, http.StatusBadRequest, "invalid code or code_verifier")
		return
	}

	takeCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	entry, err := h.opts.Store.Take(takeCtx, body.Code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) || errors.Is(err, ErrCodeMalformed) {
			writeError(w, http.StatusBadRequest, "invalid or expired code")
			return
		}
		h.opts.Logger.Error("oauth: take short code failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Verify PKCE: sha256(code_verifier) base64url-no-pad must equal the
	// challenge we stored at /authorize.
	expected := pkceChallengeFromVerifier(body.CodeVerifier)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(entry.CodeChallenge)) != 1 {
		h.audit(r.Context(), AuditEvent{
			TenantID: tenant.UserID, APIKeyID: tenant.APIKeyID,
			EventType: "oauth.token_exchanged", Provider: entry.Provider,
			Outcome: "rejected", Reason: "pkce_mismatch",
		})
		writeError(w, http.StatusBadRequest, "PKCE verifier did not match")
		return
	}

	resp := tokenExchangeResponse{IDToken: entry.IDToken, Provider: entry.Provider}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.opts.Logger.Warn("oauth: encode token-exchange response failed", "err", err)
	}
	h.audit(r.Context(), AuditEvent{
		TenantID: tenant.UserID, APIKeyID: tenant.APIKeyID,
		EventType: "oauth.token_exchanged", Provider: entry.Provider,
		Outcome: "completed",
	})
}

// --- small helpers --------------------------------------------------------

func readStateCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(StateCookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

// pkceChallengeFromVerifier returns base64url(sha256(verifier)), no padding.
func pkceChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomURLSafe returns base64url(no-pad) of `n` random bytes.
func randomURLSafe(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is fatal — there is nothing safe to do here.
		panic(fmt.Sprintf("oauth: rand.Read failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// isHTTPSOrLocal allows the local-development pattern http://localhost while
// requiring https:// everywhere else.
func isHTTPSOrLocal(uri string) bool {
	if uri == "" || len(uri) > 1024 {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1") {
		return true
	}
	return false
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
