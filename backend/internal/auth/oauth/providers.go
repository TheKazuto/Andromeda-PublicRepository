package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	githubendpoint "golang.org/x/oauth2/github"
	googleendpoint "golang.org/x/oauth2/google"
)

// ----- Google -----

type googleProvider struct {
	cfg *oauth2.Config
}

type googleProfile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func NewGoogle(clientID, clientSecret, redirectURL string) Provider {
	return &googleProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     googleendpoint.Endpoint,
		},
	}
}

func (g *googleProvider) Name() string { return "google" }

func (g *googleProvider) AuthURL(state string) string {
	return g.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (g *googleProvider) Exchange(ctx context.Context, code string) (*Profile, error) {
	tok, err := g.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google exchange: %w", err)
	}
	client := g.cfg.Client(ctx, tok)
	res, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("google userinfo: status %d: %s", res.StatusCode, string(body))
	}
	var p googleProfile
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("google decode: %w", err)
	}
	if p.Sub == "" || p.Email == "" {
		return nil, fmt.Errorf("google profile missing sub or email")
	}
	if !p.EmailVerified {
		return nil, fmt.Errorf("google email is not verified")
	}
	prof := &Profile{
		Provider: "google",
		Subject:  p.Sub,
		Email:    strings.ToLower(strings.TrimSpace(p.Email)),
		Name:     p.Name,
	}
	if err := prof.Validate(); err != nil {
		return nil, fmt.Errorf("google profile invalid: %w", err)
	}
	return prof, nil
}

// ----- GitHub -----

type githubProvider struct {
	cfg *oauth2.Config
}

type githubProfile struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func NewGitHub(clientID, clientSecret, redirectURL string) Provider {
	return &githubProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     githubendpoint.Endpoint,
		},
	}
}

func (g *githubProvider) Name() string { return "github" }

func (g *githubProvider) AuthURL(state string) string {
	return g.cfg.AuthCodeURL(state)
}

func (g *githubProvider) Exchange(ctx context.Context, code string) (*Profile, error) {
	tok, err := g.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github exchange: %w", err)
	}
	client := g.cfg.Client(ctx, tok)

	// 1. Fetch the basic profile
	userRes, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	defer userRes.Body.Close()
	if userRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userRes.Body)
		return nil, fmt.Errorf("github user: status %d: %s", userRes.StatusCode, string(body))
	}
	var p githubProfile
	if err := json.NewDecoder(userRes.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("github decode: %w", err)
	}
	if p.ID == 0 {
		return nil, fmt.Errorf("github profile missing id")
	}

	// 2. The primary email may be private — fetch /user/emails to find the
	//    verified primary.
	email := strings.ToLower(strings.TrimSpace(p.Email))
	if email == "" {
		emailsRes, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			return nil, fmt.Errorf("github emails: %w", err)
		}
		defer emailsRes.Body.Close()
		if emailsRes.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(emailsRes.Body)
			return nil, fmt.Errorf("github emails: status %d: %s", emailsRes.StatusCode, string(body))
		}
		var emails []githubEmail
		if err := json.NewDecoder(emailsRes.Body).Decode(&emails); err != nil {
			return nil, fmt.Errorf("github emails decode: %w", err)
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				email = strings.ToLower(e.Email)
				break
			}
		}
	}
	if email == "" {
		return nil, fmt.Errorf("github account has no verified primary email")
	}

	name := p.Name
	if name == "" {
		name = p.Login
	}

	prof := &Profile{
		Provider: "github",
		Subject:  fmt.Sprintf("%d", p.ID),
		Email:    email,
		Name:     name,
	}
	if err := prof.Validate(); err != nil {
		return nil, fmt.Errorf("github profile invalid: %w", err)
	}
	return prof, nil
}
