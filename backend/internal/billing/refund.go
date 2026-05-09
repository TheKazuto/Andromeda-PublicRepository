package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/refund"
)

// RefundCheckoutPayment issues a Stripe refund for a paid Checkout
// Session. The session id is what we persist on gift_cards.stripe_payment_id.
//
// Flow:
//   1. Retrieve the session to get the payment_intent id (the session
//      itself isn't refundable; the underlying payment_intent is).
//   2. Create the refund on the payment_intent.
//
// Idempotent-friendly: if the session has already been fully refunded,
// Stripe returns an error which the caller can ignore (we surface as
// ErrAlreadyRefunded so the admin handler treats it as success).
func (s *Service) RefundCheckoutPayment(ctx context.Context, sessionID string) error {
	if !s.Enabled() {
		return ErrServiceDisabled
	}
	if sessionID == "" {
		return errors.New("session id required")
	}

	sess, err := session.Get(sessionID, nil)
	if err != nil {
		return fmt.Errorf("retrieve checkout session: %w", err)
	}
	if sess.PaymentIntent == nil || sess.PaymentIntent.ID == "" {
		// Likely a free session or one that never completed payment.
		return errors.New("checkout session has no payment intent to refund")
	}

	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(sess.PaymentIntent.ID),
	}
	if _, err := refund.New(params); err != nil {
		var stripeErr *stripe.Error
		if errors.As(err, &stripeErr) {
			// Stripe rejects when there's nothing left to refund.
			if stripeErr.Code == stripe.ErrorCodeChargeAlreadyRefunded {
				return ErrAlreadyRefunded
			}
		}
		return fmt.Errorf("create refund: %w", err)
	}
	return nil
}

// ErrAlreadyRefunded indicates the underlying Stripe charge was fully
// refunded already. The admin handler treats this as success so the
// local DB row can still be flagged regardless.
var ErrAlreadyRefunded = errors.New("stripe charge already refunded")
