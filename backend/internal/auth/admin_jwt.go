package auth

import (
	"crypto/rand"
	"encoding/base64"
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

// adminJWTLeeway tolerates a small amount of clock skew between the issuing
// and verifying processes (backend ↔ gateway are not on the same host).
// 60s matches the customer JWT verifier and is well below TokenTTL.
const adminJWTLeeway = 60 * time.Second

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

	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("generate jti: %w", err)
	}

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
			ID:        base64.RawURLEncoding.EncodeToString(jtiBytes),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign admin token: %w", err)
	}
	return signed, exp, nil
}

// ParseAdminToken validates the JWT signature, expiry, issuer and that
// the role claim is populated (so a customer token cannot be replayed
// against admin routes even if the secrets ever collide).
func ParseAdminToken(secret []byte, raw string) (*AdminClaims, error) {
	if raw == "" {
		return nil, errors.New("empty token")
	}
	claims := &AdminClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	},
		jwt.WithIssuer(AdminTokenIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(adminJWTLeeway),
	)
	if err != nil {
		return nil, fmt.Errorf("parse admin token: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("invalid admin token")
	}
	if claims.Role == "" {
		return nil, errors.New("invalid admin token: missing role claim")
	}
	return claims, nil
}
