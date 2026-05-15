package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/refund"
)

// refundRetryAttempts caps how many times we retry transient Stripe
// errors (429, 5xx, network) before giving up. Three attempts with
// exponential backoff handles short Stripe blips without amplifying
// real outages.
const refundRetryAttempts = 3

// RefundCheckoutPayment issues a Stripe refund for a paid Checkout
// Session. The session id is what we persist on gift_cards.stripe_payment_id.
//
// Flow:
//  1. Retrieve the session to get the payment_intent id (the session
//     itself isn't refundable; the underlying payment_intent is).
//  2. Create the refund on the payment_intent. The call is retried
//     with exponential backoff for transient Stripe failures.
//
// Idempotent-friendly: if the session has already been fully refunded,
// Stripe returns ErrorCodeChargeAlreadyRefunded which we surface as
// ErrAlreadyRefunded so the admin handler treats it as success.
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
	// Stable Idempotency-Key — a retried request for the same session
	// will be deduplicated by Stripe itself.
	params.SetIdempotencyKey("andromeda_refund_" + sessionID)

	var lastErr error
	for attempt := 0; attempt < refundRetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(200<<uint(attempt-1)) * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if _, err := refund.New(params); err != nil {
			var stripeErr *stripe.Error
			if errors.As(err, &stripeErr) {
				if stripeErr.Code == stripe.ErrorCodeChargeAlreadyRefunded {
					return ErrAlreadyRefunded
				}
				if isTransientStripeError(stripeErr) {
					lastErr = err
					continue
				}
			}
			return fmt.Errorf("create refund: %w", err)
		}
		return nil
	}
	return fmt.Errorf("create refund: exceeded retries: %w", lastErr)
}

// isTransientStripeError reports whether the error is worth retrying.
// Permanent failures (invalid request, card declined, etc.) propagate
// immediately so the caller doesn't waste attempts on hopeless work.
// We rely on the HTTP status code rather than ErrorType because the
// stripe-go v82 ErrorType enum collapses connection / rate-limit
// failures under ErrorTypeAPI alongside other unrelated server errors.
func isTransientStripeError(e *stripe.Error) bool {
	if e == nil {
		return false
	}
	if e.HTTPStatusCode == 429 || e.HTTPStatusCode >= 500 {
		return true
	}
	if e.Type == stripe.ErrorTypeAPI {
		return true
	}
	return false
}

// ErrAlreadyRefunded indicates the underlying Stripe charge was fully
// refunded already. The admin handler treats this as success so the
// local DB row can still be flagged regardless.
var ErrAlreadyRefunded = errors.New("stripe charge already refunded")
