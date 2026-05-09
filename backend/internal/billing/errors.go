package billing

import "errors"

var (
	// ErrServiceDisabled is returned by Service methods when STRIPE_SECRET_KEY
	// is missing. Handlers should map this to HTTP 503.
	ErrServiceDisabled = errors.New("billing service disabled (STRIPE_SECRET_KEY not configured)")

	// ErrPriceNotConfigured is returned when no Stripe price id is mapped
	// for the (plan, cycle) pair. Handlers should map this to HTTP 400.
	ErrPriceNotConfigured = errors.New("stripe price not configured for plan+cycle")
)
