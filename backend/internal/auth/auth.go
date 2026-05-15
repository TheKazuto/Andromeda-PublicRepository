package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrInvalidPassword = errors.New("invalid password")
)

// TokenTTL is the lifetime of an access JWT. Kept short because the dashboard
// holds the JWT in memory only — when it expires the client falls back to
// /v1/auth/refresh, which exchanges the long-lived HttpOnly refresh cookie
// for a fresh access token. A stolen JWT (e.g. via XSS) is therefore valid
// for at most one TokenTTL, and revocation of the refresh side cuts off
// further renewals.
const TokenTTL = 1 * time.Hour

// UserBcryptCost matches the admin cost (12). The previous default (10) was
// borderline against modern GPU attacks; the extra ~150 ms is acceptable in
// the login flow.
const UserBcryptCost = 12

// TokenIssuer is the iss claim of customer JWTs — distinct from the admin
// issuer so an admin token never authenticates as a user.
const TokenIssuer = "andromeda"

type Claims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), UserBcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// VerifyPassword returns nil iff `password` matches `hash`. Returns
// ErrInvalidPassword on mismatch; other errors (corrupted hash, etc.)
// propagate so the caller can distinguish them in logs.
func VerifyPassword(password, hash string) error {
	if hash == "" {
		return ErrInvalidPassword
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidPassword
	}
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	return nil
}

// CheckPassword is a thin compatibility wrapper retained for existing
// callers. Prefer VerifyPassword in new code so the failure mode is
// distinguishable.
func CheckPassword(password, hash string) bool {
	return VerifyPassword(password, hash) == nil
}

func IssueToken(secret, userID, email string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(TokenTTL)
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    TokenIssuer,
			Subject:   userID,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, exp, nil
}

func ParseToken(secret, token string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	},
		jwt.WithIssuer(TokenIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(60*time.Second),
	)
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
