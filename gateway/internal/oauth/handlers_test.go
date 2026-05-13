package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ---------- test doubles ---------------------------------------------------

type fakeAllowlist struct{ allowed map[string]bool }

func (f *fakeAllowlist) IsAllowed(_ context.Context, userID, redirectURI string) (bool, error) {
	return f.allowed[userID+"|"+redirectURI], nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (f *fakeAudit) Append(_ context.Context, ev AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

type fakeProvider struct {
	name          ProviderName
	lastCode      string
	idToken       string
	exchangeErr   error
	authBuildSpy  func(state, nonce, redirectURI string)
}

func (p *fakeProvider) Name() ProviderName { return p.name }

func (p *fakeProvider) AuthorizationURL(state, nonce, redirectURI string) string {
	if p.authBuildSpy != nil {
		p.authBuildSpy(state, nonce, redirectURI)
	}
	q := url.Values{
		"state":        {state},
		"nonce":        {nonce},
		"redirect_uri": {redirectURI},
	}
	return "https://provider.test/authorize?" + q.Encode()
}

func (p *fakeProvider) ExchangeCode(_ context.Context, code, _ string) (string, error) {
	p.lastCode = code
	if p.exchangeErr != nil {
		return "", p.exchangeErr
	}
	return p.idToken, nil
}

// ---------- helpers --------------------------------------------------------

func newTestHandler(t *testing.T, prov Provider, allow *fakeAllowlist, audit *fakeAudit) (*Handler, *miniredis.Miniredis, func()) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st, err := NewStore(rdb, 60*time.Second)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	h, err := NewHandler(HandlerOptions{
		BaseURL:         "https://gw.test",
		StateHMACSecret: []byte(testSecret),
		IsProduction:    false,
		Providers:       map[ProviderName]Provider{prov.Name(): prov},
		Store:           st,
		Allowlist:       allow,
		Audit:           audit,
		AuthFromRequest: func(r *http.Request) (TenantInfo, bool) {
			if r.Header.Get("X-Test-Tenant") == "" {
				return TenantInfo{}, false
			}
			return TenantInfo{UserID: r.Header.Get("X-Test-Tenant"), APIKeyID: "k-1"}, true
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, mr, func() { _ = rdb.Close() }
}

// codeVerifier returns a random 43-byte base64url verifier and its S256 challenge.
func newPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	rawVerifier := make([]byte, 32)
	for i := range rawVerifier {
		rawVerifier[i] = byte(i + 1)
	}
	verifier = base64.RawURLEncoding.EncodeToString(rawVerifier)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

const sampleNonce = "pAqtrYL_Am8SKcwcG9vvIU6k4VoVNsC7V_i2a2cWuaU"

// ---------- /authorize tests ----------------------------------------------

func TestAuthorize_HappyPath_302WithStateCookie(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "X"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()

	_, ch := newPKCEPair(t)
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"google"},
		"redirect_uri":          {"https://app.test/cb"},
		"code_challenge":        {ch},
		"code_challenge_method": {"S256"},
		"nonce":                 {sampleNonce},
		"app_state":             {"client-app-state"},
	}.Encode(), nil)
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	// State cookie must be set and HttpOnly.
	cookies := rr.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == StateCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatalf("state cookie not set")
	}
	if !stateCookie.HttpOnly || stateCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie security flags wrong: %+v", stateCookie)
	}
	// Provider URL must echo the cookie value as `state` and our nonce.
	loc, _ := url.Parse(rr.Header().Get("Location"))
	q := loc.Query()
	if q.Get("state") != stateCookie.Value {
		t.Fatalf("provider state != cookie value")
	}
	if q.Get("nonce") != sampleNonce {
		t.Fatalf("provider nonce wrong: %s", q.Get("nonce"))
	}
	if q.Get("redirect_uri") != "https://gw.test/v1/oauth/callback" {
		t.Fatalf("provider redirect_uri must be the broker callback, got %s", q.Get("redirect_uri"))
	}
}

func TestAuthorize_RejectsUnknownProvider(t *testing.T) {
	allow := &fakeAllowlist{}
	h, _, cleanup := newTestHandler(t, &fakeProvider{name: ProviderGoogle}, allow, &fakeAudit{})
	defer cleanup()
	_, ch := newPKCEPair(t)
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"bing"},
		"redirect_uri":          {"https://app.test/cb"},
		"code_challenge":        {ch},
		"code_challenge_method": {"S256"},
		"nonce":                 {sampleNonce},
	}.Encode(), nil)
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

func TestAuthorize_RejectsRedirectNotInAllowlist(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	audit := &fakeAudit{}
	prov := &fakeProvider{name: ProviderGoogle}
	h, _, cleanup := newTestHandler(t, prov, allow, audit)
	defer cleanup()

	_, ch := newPKCEPair(t)
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"google"},
		"redirect_uri":          {"https://attacker.test/x"},
		"code_challenge":        {ch},
		"code_challenge_method": {"S256"},
		"nonce":                 {sampleNonce},
	}.Encode(), nil)
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rr.Code)
	}
	if len(audit.events) == 0 || audit.events[0].Reason != "redirect_not_allowed" {
		t.Fatalf("expected audit event with reason=redirect_not_allowed, got %+v", audit.events)
	}
}

func TestAuthorize_RejectsNonHTTPSRedirect(t *testing.T) {
	allow := &fakeAllowlist{}
	prov := &fakeProvider{name: ProviderGoogle}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	_, ch := newPKCEPair(t)
	cases := []string{"ftp://x.test/cb", "http://app.test/cb", "javascript:alert(1)", "not a url"}
	for _, target := range cases {
		req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
			"provider":              {"google"},
			"redirect_uri":          {target},
			"code_challenge":        {ch},
			"code_challenge_method": {"S256"},
			"nonce":                 {sampleNonce},
		}.Encode(), nil)
		req.Header.Set("X-Test-Tenant", "u-1")
		rr := httptest.NewRecorder()
		h.Authorize(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("redirect %q: got %d, want 400", target, rr.Code)
		}
	}
}

func TestAuthorize_RequiresPKCES256(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	_, ch := newPKCEPair(t)
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"google"},
		"redirect_uri":          {"https://app.test/cb"},
		"code_challenge":        {ch},
		"code_challenge_method": {"plain"},
		"nonce":                 {sampleNonce},
	}.Encode(), nil)
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

func TestAuthorize_MissingAPIKey_401(t *testing.T) {
	allow := &fakeAllowlist{}
	h, _, cleanup := newTestHandler(t, &fakeProvider{name: ProviderGoogle}, allow, &fakeAudit{})
	defer cleanup()
	_, ch := newPKCEPair(t)
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"google"},
		"redirect_uri":          {"https://app.test/cb"},
		"code_challenge":        {ch},
		"code_challenge_method": {"S256"},
		"nonce":                 {sampleNonce},
	}.Encode(), nil)
	// no X-Test-Tenant
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rr.Code)
	}
}

// ---------- /callback tests -----------------------------------------------

// authorizeRoundtrip drives /authorize end-to-end and returns the state cookie
// + the provider URL the browser was redirected to. Used as setup for
// /callback tests.
func authorizeRoundtrip(t *testing.T, h *Handler, verifier, challenge string) (*http.Cookie, string) {
	t.Helper()
	_ = verifier // silence
	req := httptest.NewRequest("GET", "/v1/oauth/authorize?"+url.Values{
		"provider":              {"google"},
		"redirect_uri":          {"https://app.test/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {sampleNonce},
		"app_state":             {"my-app-state"},
	}.Encode(), nil)
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("Authorize setup: got %d", rr.Code)
	}
	var c *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == StateCookieName {
			c = ck
		}
	}
	return c, rr.Header().Get("Location")
}

func TestCallback_HappyPath_302WithShortCode(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "ID_TOKEN_HERE"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()

	verifier, ch := newPKCEPair(t)
	cookie, _ := authorizeRoundtrip(t, h, verifier, ch)

	// Provider redirected back to /callback with the state cookie value as state.
	req := httptest.NewRequest("GET", "/v1/oauth/callback?"+url.Values{
		"code":  {"provider-code-XYZ"},
		"state": {cookie.Value},
	}.Encode(), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://app.test/cb" {
		t.Fatalf("redirected to wrong host: %s", loc.String())
	}
	shortCode := loc.Query().Get("code")
	if shortCode == "" {
		t.Fatalf("no short_code in redirect")
	}
	if loc.Query().Get("state") != "my-app-state" {
		t.Fatalf("app_state echo wrong: %s", loc.Query().Get("state"))
	}
	if prov.lastCode != "provider-code-XYZ" {
		t.Fatalf("provider not invoked with provider-code-XYZ: %s", prov.lastCode)
	}
}

func TestCallback_RejectsStateMismatch(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "X"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	cookie, _ := authorizeRoundtrip(t, h, verifier, ch)

	req := httptest.NewRequest("GET", "/v1/oauth/callback?"+url.Values{
		"code":  {"abc"},
		"state": {"tampered"},
	}.Encode(), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

func TestCallback_MissingCookie_400(t *testing.T) {
	allow := &fakeAllowlist{}
	h, _, cleanup := newTestHandler(t, &fakeProvider{name: ProviderGoogle}, allow, &fakeAudit{})
	defer cleanup()
	req := httptest.NewRequest("GET", "/v1/oauth/callback?code=x&state=y", nil)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

func TestCallback_ProviderExchangeFails_502(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, exchangeErr: errors.New("upstream 500")}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	cookie, _ := authorizeRoundtrip(t, h, verifier, ch)
	req := httptest.NewRequest("GET", "/v1/oauth/callback?"+url.Values{
		"code":  {"abc"},
		"state": {cookie.Value},
	}.Encode(), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502; body=%s", rr.Code, rr.Body.String())
	}
}

func TestCallback_ProviderErrorEcho_302WithError(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "x"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	cookie, _ := authorizeRoundtrip(t, h, verifier, ch)
	req := httptest.NewRequest("GET", "/v1/oauth/callback?"+url.Values{
		"error": {"access_denied"},
		"state": {cookie.Value},
	}.Encode(), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rr.Code)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("error not echoed: %s", loc.String())
	}
}

// ---------- /token-exchange tests -----------------------------------------

// completeAuthorizeAndCallback drives the full handshake and returns the
// short_code visible at the tenant's redirect URI.
func completeAuthorizeAndCallback(t *testing.T, h *Handler, verifier, challenge string) string {
	t.Helper()
	cookie, _ := authorizeRoundtrip(t, h, verifier, challenge)
	req := httptest.NewRequest("GET", "/v1/oauth/callback?"+url.Values{
		"code":  {"provider-code"},
		"state": {cookie.Value},
	}.Encode(), nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("callback setup: got %d", rr.Code)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	return loc.Query().Get("code")
}

func TestTokenExchange_HappyPath(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "FINAL_ID_TOKEN"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	shortCode := completeAuthorizeAndCallback(t, h, verifier, ch)

	body, _ := json.Marshal(tokenExchangeRequest{Code: shortCode, CodeVerifier: verifier})
	req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.TokenExchange(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp tokenExchangeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if resp.IDToken != "FINAL_ID_TOKEN" || resp.Provider != "google" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestTokenExchange_PKCEMismatch(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "X"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	shortCode := completeAuthorizeAndCallback(t, h, verifier, ch)

	// Send a different verifier — sha256 won't match the stored challenge.
	body, _ := json.Marshal(tokenExchangeRequest{
		Code:         shortCode,
		CodeVerifier: strings.Repeat("A", 43),
	})
	req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.TokenExchange(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestTokenExchange_SingleUse(t *testing.T) {
	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	prov := &fakeProvider{name: ProviderGoogle, idToken: "X"}
	h, _, cleanup := newTestHandler(t, prov, allow, &fakeAudit{})
	defer cleanup()
	verifier, ch := newPKCEPair(t)
	shortCode := completeAuthorizeAndCallback(t, h, verifier, ch)

	body, _ := json.Marshal(tokenExchangeRequest{Code: shortCode, CodeVerifier: verifier})
	// First exchange succeeds.
	req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.TokenExchange(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first exchange status: got %d", rr.Code)
	}
	// Second exchange with the same code must fail.
	req2 := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(string(body)))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Test-Tenant", "u-1")
	rr2 := httptest.NewRecorder()
	h.TokenExchange(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("second exchange should 400, got %d", rr2.Code)
	}
}

func TestTokenExchange_RejectsBadBody(t *testing.T) {
	allow := &fakeAllowlist{}
	h, _, cleanup := newTestHandler(t, &fakeProvider{name: ProviderGoogle}, allow, &fakeAudit{})
	defer cleanup()

	cases := []string{"not json", `{"code":"short"}`, `{"unknown":"f"}`}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(c))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Tenant", "u-1")
		rr := httptest.NewRecorder()
		h.TokenExchange(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d, want 400", c, rr.Code)
		}
	}
}

func TestTokenExchange_RejectsNonJSONContentType(t *testing.T) {
	allow := &fakeAllowlist{}
	h, _, cleanup := newTestHandler(t, &fakeProvider{name: ProviderGoogle}, allow, &fakeAudit{})
	defer cleanup()
	req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(`{"code":"x"}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Test-Tenant", "u-1")
	rr := httptest.NewRecorder()
	h.TokenExchange(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got %d, want 415", rr.Code)
	}
}

// ---------- end-to-end against a real httptest provider --------------------

// TestEndToEnd_RealProviderMock wires a Google-style mock provider on a real
// HTTP server and runs the full handshake from /authorize → /callback →
// /token-exchange. Validates that postTokenForm + Google adapter integrate
// against a typical OAuth2 token endpoint.
func TestEndToEnd_RealProviderMock(t *testing.T) {
	// Mock Google token endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", 400)
			return
		}
		if r.PostForm.Get("grant_type") != "authorization_code" {
			http.Error(w, "wrong grant", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id_token":"E2E_ID_TOKEN"}`)
	}))
	defer srv.Close()

	allow := &fakeAllowlist{allowed: map[string]bool{"u-1|https://app.test/cb": true}}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	st, _ := NewStore(rdb, 60*time.Second)

	// Custom provider whose ExchangeCode hits our mock server. We reuse the
	// real postTokenForm so the integration covers Content-Type, body parse,
	// and HTTP error handling.
	provider := &realEndpointProvider{
		name:   ProviderGoogle,
		client: srv.Client(),
		url:    srv.URL,
	}

	h, _ := NewHandler(HandlerOptions{
		BaseURL:         "https://gw.test",
		StateHMACSecret: []byte(testSecret),
		Providers:       map[ProviderName]Provider{ProviderGoogle: provider},
		Store:           st,
		Allowlist:       allow,
		AuthFromRequest: func(r *http.Request) (TenantInfo, bool) {
			return TenantInfo{UserID: "u-1", APIKeyID: "k-1"}, true
		},
	})

	verifier, ch := newPKCEPair(t)
	shortCode := completeAuthorizeAndCallback(t, h, verifier, ch)
	body, _ := json.Marshal(tokenExchangeRequest{Code: shortCode, CodeVerifier: verifier})
	req := httptest.NewRequest("POST", "/v1/oauth/token-exchange", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.TokenExchange(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("token-exchange: got %d, body=%s", rr.Code, rr.Body.String())
	}
	var resp tokenExchangeResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.IDToken != "E2E_ID_TOKEN" {
		t.Fatalf("want E2E_ID_TOKEN, got %q", resp.IDToken)
	}
}

// realEndpointProvider is fakeProvider's cousin that actually hits an HTTP
// endpoint via postTokenForm — used by the end-to-end test above.
type realEndpointProvider struct {
	name   ProviderName
	client *http.Client
	url    string
}

func (p *realEndpointProvider) Name() ProviderName { return p.name }

func (p *realEndpointProvider) AuthorizationURL(state, nonce, redirectURI string) string {
	q := url.Values{"state": {state}, "nonce": {nonce}, "redirect_uri": {redirectURI}}
	return "https://example.test/auth?" + q.Encode()
}

func (p *realEndpointProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {"cid"},
		"client_secret": {"sec"},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	return postTokenForm(ctx, p.client, p.url, form)
}
