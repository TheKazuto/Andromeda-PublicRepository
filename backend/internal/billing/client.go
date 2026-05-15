// Package billing wraps Stripe SDK calls so the rest of the gateway never
// imports stripe-go directly. Two responsibilities live here:
//
//  1. Customer + Checkout: create a Stripe Customer for an Andromeda user
//     lazily on first checkout, then build a Stripe Checkout Session for
//     the chosen plan + billing cycle.
//  2. Webhook event handling: parse incoming events with the webhook
//     secret and apply state mutations to our subscription tables
//     (handled in webhook.go in this package).
//
// The Service is constructed once at boot and shared across handlers.
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
)

// Service is the high-level billing facade.
type Service struct {
	apiKey        string
	webhookSecret string
	priceIDs      map[string]string // "pro:monthly" -> "price_..."
	successURL    string
	cancelURL     string
	logger        *slog.Logger
}

// Options is the bundle of configuration the Service needs at boot.
type Options struct {
	APIKey        string
	WebhookSecret string
	PriceIDsJSON  string // raw env value
	SuccessURL    string
	CancelURL     string
	Logger        *slog.Logger
}

// New parses the config and returns a Service. When APIKey is empty the
// returned Service has Enabled() == false; callers should check before
// invoking endpoints.
func New(opts Options) (*Service, error) {
	priceIDs := map[string]string{}
	if strings.TrimSpace(opts.PriceIDsJSON) != "" {
		if err := json.Unmarshal([]byte(opts.PriceIDsJSON), &priceIDs); err != nil {
			return nil, fmt.Errorf("parse STRIPE_PRICES_JSON: %w", err)
		}
	}
	if opts.APIKey != "" {
		// stripe-go uses a process-global API key. Setting it here means
		// every subsequent call from any package targets the configured
		// account — we don't manually pass it on each call.
		stripe.Key = opts.APIKey
	}
	return &Service{
		apiKey:        opts.APIKey,
		webhookSecret: opts.WebhookSecret,
		priceIDs:      priceIDs,
		successURL:    opts.SuccessURL,
		cancelURL:     opts.CancelURL,
		logger:        opts.Logger,
	}, nil
}

// Enabled reports whether the service has a Stripe API key configured.
// When false, callers should respond with 503 service_unavailable on
// billing endpoints.
func (s *Service) Enabled() bool {
	return s.apiKey != ""
}

// WebhookSecret returns the webhook signing secret. Empty when not
// configured — handlers should refuse to process events.
func (s *Service) WebhookSecret() string { return s.webhookSecret }

// PriceID looks up the Stripe price id for a (plan, cycle) pair. Returns
// ErrPriceNotConfigured when the mapping is missing.
func (s *Service) PriceID(planCode, cycle string) (string, error) {
	if !s.Enabled() {
		return "", ErrServiceDisabled
	}
	key := strings.ToLower(planCode) + ":" + strings.ToLower(cycle)
	id, ok := s.priceIDs[key]
	if !ok || id == "" {
		return "", fmt.Errorf("%w: %s", ErrPriceNotConfigured, key)
	}
	return id, nil
}

// EnsureCustomer returns the Stripe customer id for the user. If the
// supplied existingID is non-empty, it is returned as-is (one Stripe
// customer per user, ever). Otherwise a new customer is created with
// an Idempotency-Key derived from the user id — Stripe deduplicates
// for 24 h, so a transient network failure between Stripe creation
// and our local persistence cannot strand a duplicate customer.
func (s *Service) EnsureCustomer(ctx context.Context, existingID, email, userID string) (string, error) {
	if !s.Enabled() {
		return "", ErrServiceDisabled
	}
	if strings.TrimSpace(existingID) != "" {
		return existingID, nil
	}
	if email == "" {
		return "", errors.New("email required to create Stripe customer")
	}
	if userID == "" {
		return "", errors.New("user id required to create Stripe customer")
	}
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
	}
	params.AddMetadata("andromeda_user_id", userID)
	// Stable per-user Idempotency-Key. Two parallel checkout attempts
	// for the same user collapse to one Stripe customer; a retry after
	// a network blip returns the previously created object.
	params.SetIdempotencyKey("andromeda_customer_" + userID)
	c, err := customer.New(params)
	if err != nil {
		return "", fmt.Errorf("create stripe customer: %w", err)
	}
	return c.ID, nil
}

// CreateCheckoutSessionInput is the payload for building a hosted
// Checkout Session URL.
type CreateCheckoutSessionInput struct {
	UserID             string
	UserEmail          string
	StripeCustomerID   string // empty → EnsureCustomer creates one
	PlanCode           string
	Cycle              string // 'monthly' | 'annual'
	SuccessURLOverride string // optional per-call override
	CancelURLOverride  string
}

// CheckoutSessionResult bundles what callers need to continue the flow:
// the URL to redirect the browser to, the session id, and the customer
// id (newly created or reused).
type CheckoutSessionResult struct {
	URL              string
	SessionID        string
	StripeCustomerID string
}

// CreateCheckoutSession builds a Stripe Checkout Session for a paid plan.
// The price is resolved from the (plan, cycle) → price id map. Free and
// enterprise plans are not eligible — those return ErrPriceNotConfigured.
func (s *Service) CreateCheckoutSession(ctx context.Context, in CreateCheckoutSessionInput) (*CheckoutSessionResult, error) {
	if !s.Enabled() {
		return nil, ErrServiceDisabled
	}
	priceID, err := s.PriceID(in.PlanCode, in.Cycle)
	if err != nil {
		return nil, err
	}
	customerID, err := s.EnsureCustomer(ctx, in.StripeCustomerID, in.UserEmail, in.UserID)
	if err != nil {
		return nil, err
	}

	successURL := firstNonEmpty(in.SuccessURLOverride, s.successURL)
	cancelURL := firstNonEmpty(in.CancelURLOverride, s.cancelURL)
	if successURL == "" || cancelURL == "" {
		return nil, errors.New("checkout success_url and cancel_url must be configured")
	}

	params := &stripe.CheckoutSessionParams{
		Mode:     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		Customer: stripe.String(customerID),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL:       stripe.String(successURL),
		CancelURL:        stripe.String(cancelURL),
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{},
	}
	params.AddMetadata("andromeda_user_id", in.UserID)
	params.AddMetadata("plan_code", in.PlanCode)
	params.AddMetadata("cycle", in.Cycle)
	params.SubscriptionData.AddMetadata("andromeda_user_id", in.UserID)
	params.SubscriptionData.AddMetadata("plan_code", in.PlanCode)
	params.SubscriptionData.AddMetadata("cycle", in.Cycle)
	sess, err := session.New(params)
	if err != nil {
		return nil, fmt.Errorf("create checkout session: %w", err)
	}
	return &CheckoutSessionResult{
		URL:              sess.URL,
		SessionID:        sess.ID,
		StripeCustomerID: customerID,
	}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
