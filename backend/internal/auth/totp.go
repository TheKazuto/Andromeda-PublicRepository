package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the label shown in authenticator apps (1Password, Authy,
// Google Authenticator).
const TOTPIssuer = "Andromeda"

// TOTPPeriodSeconds is the rotation period for TOTP codes. RFC 6238
// recommends 30s, which is also the default of pquerna/otp.
const TOTPPeriodSeconds = 30

// ErrTOTPReplay is returned when the supplied code is technically valid
// but its window has already been consumed (replay attempt).
var ErrTOTPReplay = errors.New("totp code already used")

// TOTPSetup is the bundle returned when an admin opts into TOTP.
//
//   - Secret is the shared secret to store in admin_users.mfa_secret.
//   - URI is the otpauth:// URL to render as a QR code in the dashboard.
type TOTPSetup struct {
	Secret string
	URI    string
}

// GenerateTOTP creates a fresh TOTP secret + provisioning URI. Account
// (commonly the admin email) is what the authenticator will display.
func GenerateTOTP(account string) (*TOTPSetup, error) {
	if account == "" {
		return nil, errors.New("account required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: account,
		Period:      TOTPPeriodSeconds,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // SHA1 is the broadest authenticator-app support
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}
	return &TOTPSetup{
		Secret: key.Secret(),
		URI:    key.URL(),
	}, nil
}

// CurrentTOTPWindow returns the TOTP window index (= unix / period) for
// the current time. The window is what we persist per-admin to enforce
// single-use within the rotation period.
func CurrentTOTPWindow() int64 {
	return time.Now().Unix() / int64(TOTPPeriodSeconds)
}

// VerifyTOTP validates a 6-digit code against the stored secret and
// rejects replays by comparing against the last accepted window.
//
// `lastWindow` is the window index previously consumed by this admin
// (zero means "never used"). On success the function returns the new
// window index — the caller persists it via SetAdminTOTPLastWindow so
// subsequent attempts at the same window are refused.
func VerifyTOTP(secret, code string, lastWindow int64) (int64, error) {
	if secret == "" {
		return 0, errors.New("secret missing")
	}
	if len(code) != 6 {
		return 0, errors.New("invalid code length")
	}
	if !totp.Validate(code, secret) {
		return 0, errors.New("invalid code")
	}
	window := CurrentTOTPWindow()
	if window <= lastWindow {
		return 0, ErrTOTPReplay
	}
	return window, nil
}
