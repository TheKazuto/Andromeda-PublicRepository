package oauth

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func sampleClaims(now int64) StateClaims {
	return StateClaims{
		TenantID:      "user-1",
		Provider:      "google",
		RedirectURI:   "https://app.example.com/cb",
		AppState:      "abc",
		CodeChallenge: "K_OBYRRPnFmJZG3MWv-VPyzU0R2gZqYbVm54iUg2C2A",
		Nonce:         "pAqtrYL_Am8SKcwcG9vvIU6k4VoVNsC7V_i2a2cWuaU",
		IssuedAt:      now,
		CSRF:          "x",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Now()
	in := sampleClaims(now.Unix())
	signed, err := SignState([]byte(testSecret), in)
	if err != nil {
		t.Fatalf("SignState: %v", err)
	}
	out, err := VerifyState([]byte(testSecret), signed, now)
	if err != nil {
		t.Fatalf("VerifyState: %v", err)
	}
	if out.TenantID != in.TenantID || out.Provider != in.Provider ||
		out.RedirectURI != in.RedirectURI || out.AppState != in.AppState ||
		out.CodeChallenge != in.CodeChallenge || out.Nonce != in.Nonce ||
		out.CSRF != in.CSRF || out.IssuedAt != in.IssuedAt {
		t.Fatalf("claims mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestVerifyState_TamperedPayload(t *testing.T) {
	now := time.Now()
	signed, _ := SignState([]byte(testSecret), sampleClaims(now.Unix()))
	dot := strings.IndexByte(signed, '.')
	// Flip one character of the payload — signature won't match.
	tampered := signed[:dot-1] + "X" + signed[dot:]
	if _, err := VerifyState([]byte(testSecret), tampered, now); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestVerifyState_TamperedSignature(t *testing.T) {
	now := time.Now()
	signed, _ := SignState([]byte(testSecret), sampleClaims(now.Unix()))
	// Flip the last char of the signature.
	tampered := signed[:len(signed)-1] + flipChar(signed[len(signed)-1])
	if _, err := VerifyState([]byte(testSecret), tampered, now); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func flipChar(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestVerifyState_WrongSecret(t *testing.T) {
	now := time.Now()
	signed, _ := SignState([]byte(testSecret), sampleClaims(now.Unix()))
	if _, err := VerifyState([]byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"), signed, now); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState with wrong secret, got %v", err)
	}
}

func TestVerifyState_TTLExpired(t *testing.T) {
	mintedAt := time.Now().Add(-StateCookieTTL - time.Minute)
	signed, _ := SignState([]byte(testSecret), sampleClaims(mintedAt.Unix()))
	if _, err := VerifyState([]byte(testSecret), signed, time.Now()); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState on expired cookie, got %v", err)
	}
}

func TestVerifyState_FutureMintedSlightSkewOK(t *testing.T) {
	// 30s skew is within the tolerance — VerifyState must accept it.
	mintedAt := time.Now().Add(30 * time.Second)
	signed, _ := SignState([]byte(testSecret), sampleClaims(mintedAt.Unix()))
	if _, err := VerifyState([]byte(testSecret), signed, time.Now()); err != nil {
		t.Fatalf("expected slight clock skew to be accepted, got %v", err)
	}
}

func TestVerifyState_FutureMintedTooFarRejected(t *testing.T) {
	// 5min skew is outside the tolerance.
	mintedAt := time.Now().Add(5 * time.Minute)
	signed, _ := SignState([]byte(testSecret), sampleClaims(mintedAt.Unix()))
	if _, err := VerifyState([]byte(testSecret), signed, time.Now()); err != ErrInvalidState {
		t.Fatalf("expected far-future to be rejected, got %v", err)
	}
}

func TestSignState_RejectsShortSecret(t *testing.T) {
	if _, err := SignState([]byte("short"), sampleClaims(0)); err == nil {
		t.Fatalf("expected error for short secret")
	}
}

func TestVerifyState_RejectsMissingDot(t *testing.T) {
	if _, err := VerifyState([]byte(testSecret), "nodot", time.Now()); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
	if _, err := VerifyState([]byte(testSecret), "", time.Now()); err != ErrInvalidState {
		t.Fatalf("expected ErrInvalidState on empty, got %v", err)
	}
}
