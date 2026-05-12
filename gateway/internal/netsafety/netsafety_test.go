package netsafety

import (
	"context"
	"errors"
	"net"
	"testing"
)

// withResolver returns a Validator whose DNS lookup is replaced by a stub.
func withResolver(mode Mode, fn func(host string) ([]net.IP, error)) *Validator {
	v := New(mode)
	v.resolve = func(_ context.Context, host string) ([]net.IP, error) { return fn(host) }
	return v
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"0.0.0.0",             // unspecified
		"169.254.169.254",     // AWS/GCP metadata + link-local
		"100.100.100.200",     // Alibaba metadata
		"10.1.2.3",            // private
		"192.168.0.1",         // private
		"172.16.5.5",          // private
		"100.64.0.1",          // CGNAT
		"100.127.255.255",     // CGNAT upper bound
		"fc00::1", "fd12::34", // IPv6 ULA
		"fe80::1",   // IPv6 link-local
		"ff02::1",   // IPv6 multicast
		"224.0.0.1", // IPv4 multicast
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}
	allowed := []string{"1.2.3.4", "8.8.8.8", "2001:db8::1", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}
	if !isBlockedIP(nil) {
		t.Error("isBlockedIP(nil) = false, want true")
	}
}

func TestValidateRegister_StaticChecks(t *testing.T) {
	// No DNS involved for any of these — all rejected (or accepted) by parseAndCheck.
	v := withResolver(ModeProduction, func(string) ([]net.IP, error) {
		t.Fatal("resolver should not be called")
		return nil, nil
	})
	bad := []string{
		"",                               // empty
		"::::not a url",                  // unparsable
		"https://user:pw@example.com",    // credentials
		"https://",                       // missing host
		"http://example.com",             // http not allowed in prod
		"ftp://example.com",              // bad scheme
		"https://127.0.0.1",              // literal loopback
		"https://169.254.169.254/latest", // literal metadata
		"https://10.0.0.5",               // literal private
		"https://100.64.1.2",             // literal CGNAT
		"https://[::1]",                  // literal v6 loopback
		"https://[fc00::1]",              // literal v6 ULA
	}
	for _, raw := range bad {
		if err := v.ValidateRegister(context.Background(), raw); err == nil {
			t.Errorf("ValidateRegister(%q) = nil, want blocked", raw)
		} else if !errors.Is(err, ErrBlockedURL) {
			t.Errorf("ValidateRegister(%q) error %v not wrapping ErrBlockedURL", raw, err)
		}
	}
	// A public literal IP over https needs no DNS and is allowed.
	if err := v.ValidateRegister(context.Background(), "https://8.8.8.8/hook"); err != nil {
		t.Errorf("ValidateRegister(https://8.8.8.8) = %v, want nil", err)
	}
}

func TestValidateRegister_DevMode(t *testing.T) {
	v := withResolver(ModeDevelopment, func(string) ([]net.IP, error) {
		t.Fatal("resolver should not be called for loopback")
		return nil, nil
	})
	ok := []string{
		"http://localhost:3000/hook",
		"http://127.0.0.1:8091/cb",
		"https://localhost",
		"https://127.0.0.1",
		"https://[::1]",
	}
	for _, raw := range ok {
		if err := v.ValidateRegister(context.Background(), raw); err != nil {
			t.Errorf("dev ValidateRegister(%q) = %v, want nil", raw, err)
		}
	}
	// http to a non-loopback host is still rejected in dev.
	if err := v.ValidateRegister(context.Background(), "http://example.com"); err == nil {
		t.Error("dev ValidateRegister(http://example.com) = nil, want blocked")
	}
	// http to a private-range IP is rejected even in dev.
	if err := v.ValidateRegister(context.Background(), "http://10.0.0.5"); err == nil {
		t.Error("dev ValidateRegister(http://10.0.0.5) = nil, want blocked")
	}
}

func TestValidateRegister_DNS(t *testing.T) {
	t.Run("resolves to public IP", func(t *testing.T) {
		v := withResolver(ModeProduction, func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		})
		if err := v.ValidateRegister(context.Background(), "https://hooks.example.com/x"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("resolves to blocked IP", func(t *testing.T) {
		v := withResolver(ModeProduction, func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("169.254.169.254")}, nil
		})
		if err := v.ValidateRegister(context.Background(), "https://rebind.example.com/x"); err == nil {
			t.Fatal("want blocked, got nil")
		}
	})
	t.Run("dns error", func(t *testing.T) {
		v := withResolver(ModeProduction, func(string) ([]net.IP, error) {
			return nil, errors.New("nxdomain")
		})
		if err := v.ValidateRegister(context.Background(), "https://missing.example.com"); err == nil {
			t.Fatal("want blocked, got nil")
		}
	})
	t.Run("dns empty", func(t *testing.T) {
		v := withResolver(ModeProduction, func(string) ([]net.IP, error) { return nil, nil })
		if err := v.ValidateRegister(context.Background(), "https://empty.example.com"); err == nil {
			t.Fatal("want blocked, got nil")
		}
	})
}

func TestValidateDispatch_MatchesRegister(t *testing.T) {
	// Dispatch re-resolves: a host that was clean at register time but now
	// resolves to a blocked IP must be rejected.
	v := withResolver(ModeProduction, func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	if err := v.ValidateDispatch(context.Background(), "https://now-evil.example.com"); err == nil {
		t.Fatal("ValidateDispatch should re-check DNS and block")
	}
}
