package auth

import (
	"errors"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the label shown in authenticator apps (1Password, Authy,
// Google Authenticator).
const TOTPIssuer = "Andromeda"

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
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // SHA1 is the broadest authenticator-app support
	})
	if err != nil {
		return nil, err
	}
	return &TOTPSetup{
		Secret: key.Secret(),
		URI:    key.URL(),
	}, nil
}

// VerifyTOTP validates a 6-digit code against the stored secret.
// Returns nil on success, an error on mismatch or malformed inputs.
func VerifyTOTP(secret, code string) error {
	if secret == "" {
		return errors.New("secret missing")
	}
	if len(code) != 6 {
		return errors.New("invalid code length")
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	return nil
}
