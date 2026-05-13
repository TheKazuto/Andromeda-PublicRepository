package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/oauth"
)

// mountOAuthBroker registers the Login Social broker routes on `r` when
// OAUTH_BROKER_ENABLED=true. No-op (logs once) when disabled.
//
//   GET  /v1/oauth/authorize       — X-Api-Key required
//   GET  /v1/oauth/callback        — browser, no X-Api-Key
//   POST /v1/oauth/token-exchange  — X-Api-Key required
//
// Returns nil only if the broker is fully built (or disabled). A
// configuration error here is fatal — the caller logs the error and
// continues serving without the broker mounted.
func (s *Server) mountOAuthBroker(r chi.Router) error {
	bc := s.cfg.OAuthBroker
	if !bc.Enabled {
		s.logger.Info("oauth broker disabled (OAUTH_BROKER_ENABLED=false)")
		return nil
	}
	if s.rdb == nil {
		// Should never happen — config.validate() blocks Enabled=true without
		// REDIS_URL — but be defensive in case validation is bypassed.
		s.logger.Error("oauth broker: REDIS_URL is required")
		return nil
	}

	providers := map[oauth.ProviderName]oauth.Provider{}
	if bc.GoogleEnabled {
		providers[oauth.ProviderGoogle] = oauth.NewGoogleProvider(
			bc.GoogleClientID, bc.GoogleClientSecret, nil,
		)
	}
	if bc.AppleEnabled {
		ap, err := oauth.NewAppleProvider(
			bc.AppleServiceID, bc.AppleTeamID, bc.AppleKeyID, bc.ApplePrivateKey, nil,
		)
		if err != nil {
			s.logger.Error("oauth broker: failed to build Apple provider", "err", err)
			return err
		}
		providers[oauth.ProviderApple] = ap
	}

	store, err := oauth.NewStore(s.rdb, time.Duration(bc.CodeTTLSeconds)*time.Second)
	if err != nil {
		s.logger.Error("oauth broker: failed to build Redis store", "err", err)
		return err
	}

	allowlist := &oauthAllowlistBridge{srv: s}
	auditBridge := &oauthAuditBridge{rec: s.auditRecorder}

	h, err := oauth.NewHandler(oauth.HandlerOptions{
		BaseURL:         bc.BaseURL,
		StateHMACSecret: []byte(bc.StateHMACSecret),
		IsProduction:    s.cfg.IsProduction(),
		Providers:       providers,
		Store:           store,
		Allowlist:       allowlist,
		Audit:           auditBridge,
		Logger:          s.logger,
		AuthFromRequest: oauthAuthFromRequest,
	})
	if err != nil {
		s.logger.Error("oauth broker: NewHandler failed", "err", err)
		return err
	}

	// Routes. /authorize and /token-exchange go behind X-Api-Key; /callback
	// is hit by the browser after the provider redirect (no X-Api-Key —
	// the cookie-bound state proves continuity from /authorize).
	r.Group(func(sub chi.Router) {
		sub.Use(s.requireAPIKey)
		sub.Get("/v1/oauth/authorize", h.Authorize)
	})
	r.Get("/v1/oauth/callback", h.Callback)
	r.Group(func(sub chi.Router) {
		sub.Use(s.requireAPIKey)
		sub.Use(limitPayload(4 << 10)) // 4 KiB cap on the token-exchange body
		sub.Post("/v1/oauth/token-exchange", h.TokenExchange)
	})

	s.logger.Info("oauth broker enabled",
		"google", bc.GoogleEnabled, "apple", bc.AppleEnabled, "base_url", bc.BaseURL)
	return nil
}

// oauthAuthFromRequest adapts the gateway's authedRequest context into the
// minimal TenantInfo the oauth package expects. Returns ok=false when the
// X-Api-Key middleware did not run or the request is anonymous.
func oauthAuthFromRequest(r *http.Request) (oauth.TenantInfo, bool) {
	a := authFrom(r)
	if a == nil || a.User == nil || a.APIKey == nil {
		return oauth.TenantInfo{}, false
	}
	return oauth.TenantInfo{UserID: a.User.ID, APIKeyID: a.APIKey.ID}, true
}

// oauthAllowlistBridge plugs the gateway's pg-backed tenant_oauth_redirects
// lookup into the oauth package without exposing pgx in there.
type oauthAllowlistBridge struct{ srv *Server }

func (b *oauthAllowlistBridge) IsAllowed(ctx context.Context, userID, redirectURI string) (bool, error) {
	return b.srv.store.IsTenantOAuthRedirectAllowed(ctx, userID, redirectURI)
}

// oauthAuditBridge adapts audit.Recorder to oauth.AuditAppender. Builds the
// canonical audit envelope from the broker-local event shape.
type oauthAuditBridge struct{ rec *audit.Recorder }

func (b *oauthAuditBridge) Append(ctx context.Context, ev oauth.AuditEvent) error {
	if b.rec == nil {
		// Audit disabled in this gateway instance — no-op (the route still works).
		return nil
	}
	apiKeyID, err := uuid.Parse(ev.APIKeyID)
	if err != nil {
		// /callback events have no API key — fall back to the all-zero
		// uuid so the entry still lands. The TenantID in payload binds it.
		apiKeyID = uuid.Nil
	}
	payload := map[string]any{
		"provider": ev.Provider,
		"outcome":  ev.Outcome,
	}
	if ev.Reason != "" {
		payload["reason"] = ev.Reason
	}
	_, err = b.rec.Append(ctx, audit.Event{
		APIKeyID:     apiKeyID,
		EventType:    ev.EventType,
		ResourceType: audit.ResourceOauth,
		ResourceID:   ev.TenantID,
		Actor:        "tenant:" + ev.TenantID,
		Payload:      payload,
	})
	return err
}
