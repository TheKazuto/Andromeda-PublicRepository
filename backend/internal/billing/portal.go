package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/billingportal/session"
)

// CreatePortalSession returns a hosted Stripe Customer Portal URL for
// the authenticated user. The portal lets them update payment method,
// download invoices, swap plan or cancel — all changes flow back via
// the existing webhook handlers, so we don't duplicate state-machine
// logic here.
//
// Returns ErrServiceDisabled when Stripe is not configured.
func (s *Service) CreatePortalSession(ctx context.Context, stripeCustomerID, returnURL string) (string, error) {
	if !s.Enabled() {
		return "", ErrServiceDisabled
	}
	if stripeCustomerID == "" {
		return "", errors.New("stripe customer id required (user has not gone through checkout yet)")
	}
	if returnURL == "" {
		return "", errors.New("return url required")
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(stripeCustomerID),
		ReturnURL: stripe.String(returnURL),
	}
	sess, err := session.New(params)
	if err != nil {
		return "", fmt.Errorf("create portal session: %w", err)
	}
	return sess.URL, nil
}
