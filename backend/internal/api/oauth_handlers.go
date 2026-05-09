package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-backend/internal/auth/oauth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// handleOAuthStart redirects the browser to the provider's authorization URL
// with a freshly minted, HMAC-signed state token.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(chi.URLParam(r, "provider"))
	provider, ok := s.oauthRegistry.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "provider not enabled")
		return
	}
	state, err := oauth.NewState([]byte(s.cfg.OAuth.StateSecret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start oauth flow")
		return
	}
	http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
}

// handleOAuthCallback validates state, exchanges the code, and finishes by
// redirecting the browser back to the dashboard with a JWT in the URL fragment.
//
// We use a 302 to <DASHBOARD_URL>/auth/callback#token=<jwt> so the token never
// reaches a server log: fragments are not sent to servers.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(chi.URLParam(r, "provider"))
	provider, ok := s.oauthRegistry.Get(name)
	if !ok {
		s.redirectWithError(w, r, "provider_not_enabled")
		return
	}

	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		s.redirectWithError(w, r, errCode)
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		s.redirectWithError(w, r, "missing_params")
		return
	}
	if err := oauth.VerifyState([]byte(s.cfg.OAuth.StateSecret), state); err != nil {
		s.redirectWithError(w, r, "invalid_state")
		return
	}

	profile, err := provider.Exchange(r.Context(), code)
	if err != nil {
		s.redirectWithError(w, r, "exchange_failed")
		return
	}

	user, err := s.findOrCreateOAuthUser(r.Context(), profile)
	if err != nil {
		s.redirectWithError(w, r, "account_error")
		return
	}

	// issueSession both mints the access JWT and sets the HttpOnly refresh
	// cookie. The JWT is forwarded in the URL fragment so the dashboard
	// callback page can pick it up without ever sending it to a server log
	// (fragments are not transmitted in the Referer header).
	tok, _, err := s.issueSession(r.Context(), w, r, user, "")
	if err != nil {
		s.redirectWithError(w, r, "token_error")
		return
	}

	s.redirectWithToken(w, r, tok)
}

// findOrCreateOAuthUser implements the email-collision policy:
//
//  1. If (provider, subject) is already linked, return that user.
//  2. If a user exists with the same email, link the OAuth identity to it
//     and return that user — same UX whether they signed up with password
//     or via another provider on the same email.
//  3. Otherwise, create a fresh user with no password hash.
func (s *Server) findOrCreateOAuthUser(ctx context.Context, p *oauth.Profile) (*store.User, error) {
	if u, err := s.store.GetUserByProvider(ctx, p.Provider, p.Subject); err == nil {
		return u, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if u, err := s.store.GetUserByEmail(ctx, p.Email); err == nil {
		if linkErr := s.store.LinkProvider(ctx, u.ID, p.Provider, p.Subject); linkErr != nil {
			return nil, linkErr
		}
		return u, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = strings.SplitN(p.Email, "@", 2)[0]
	}
	user := &store.User{
		ID:        uuid.NewString(),
		Email:     p.Email,
		Name:      name,
		Plan:      "explorer",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	if err := s.store.LinkProvider(ctx, user.ID, p.Provider, p.Subject); err != nil {
		return nil, err
	}
	// Auto-assign Free plan so OAuth signups can mint working API keys
	// without going through admin. Non-fatal on failure.
	if _, err := s.store.AssignPlan(ctx, user.ID, "free"); err != nil {
		log.Printf("auto-assign free plan failed for oauth user=%s: %v", user.ID, err)
	}
	return user, nil
}

func (s *Server) redirectWithToken(w http.ResponseWriter, r *http.Request, token string) {
	dest := s.cfg.OAuth.DashboardURL + "/auth/callback#token=" + url.QueryEscape(token)
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, code string) {
	dest := s.cfg.OAuth.DashboardURL + "/auth/callback#error=" + url.QueryEscape(code)
	http.Redirect(w, r, dest, http.StatusFound)
}
