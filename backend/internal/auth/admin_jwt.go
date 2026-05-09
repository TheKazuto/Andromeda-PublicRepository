package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AdminTokenTTL is how long an admin JWT stays valid. 8h forces re-login
// at least once a day; no refresh tokens — admins re-authenticate.
const AdminTokenTTL = 8 * time.Hour

// AdminTokenIssuer identifies the JWT's iss claim. Distinct from the
// user-token issuer so a customer JWT cannot impersonate an admin.
const AdminTokenIssuer = "andromeda-backend-admin"

// AdminClaims is the payload of an admin JWT.
type AdminClaims struct {
	AdminID string `json:"sub"`
	Email   string `json:"email"`
	Role    string `json:"role"` // 'super_admin' | 'support' | 'billing'
	jwt.RegisteredClaims
}

// IssueAdminToken signs a new JWT for an admin. Caller is responsible
// for ensuring the admin is active and (if MFA required) has passed
// the second factor.
func IssueAdminToken(secret []byte, adminID, email, role string) (string, time.Time, error) {
	if len(secret) < 32 {
		return "", time.Time{}, errors.New("admin jwt secret must be at least 32 bytes")
	}
	now := time.Now().UTC()
	exp := now.Add(AdminTokenTTL)
	claims := AdminClaims{
		AdminID: adminID,
		Email:   email,
		Role:    role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    AdminTokenIssuer,
			Subject:   adminID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        adminID + ":" + fmt.Sprintf("%d", now.UnixNano()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// ParseAdminToken validates the JWT signature, expiry, and issuer.
// Returns the claims when valid.
func ParseAdminToken(secret []byte, raw string) (*AdminClaims, error) {
	if raw == "" {
		return nil, errors.New("empty token")
	}
	claims := &AdminClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	},
		jwt.WithIssuer(AdminTokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse admin token: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("invalid admin token")
	}
	return claims, nil
}
