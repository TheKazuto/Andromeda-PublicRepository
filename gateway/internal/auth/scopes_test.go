package auth

import "testing"

func TestHasScope(t *testing.T) {
	cases := []struct {
		name     string
		granted  []string
		required string
		want     bool
	}{
		{"empty grant is wildcard", nil, ScopeWrite, true},
		{"explicit wildcard", []string{ScopeWildcard}, ScopeAdmin, true},
		{"exact match", []string{ScopeRead, ScopeWrite}, ScopeWrite, true},
		{"missing scope", []string{ScopeRead}, ScopeWrite, false},
		{"admin not implied by write", []string{ScopeWrite}, ScopeAdmin, false},
		{"wildcard among others", []string{ScopeRead, ScopeWildcard}, ScopeAdmin, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HasScope(c.granted, c.required); got != c.want {
				t.Fatalf("HasScope(%v, %q) = %v, want %v", c.granted, c.required, got, c.want)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	if got := ValidateScopes([]string{ScopeRead, ScopeWrite, ScopeAdmin, ScopeWildcard}); got != "" {
		t.Fatalf("ValidateScopes(all valid) = %q, want empty", got)
	}
	if got := ValidateScopes([]string{ScopeRead, "bogus"}); got != "bogus" {
		t.Fatalf("ValidateScopes(with typo) = %q, want %q", got, "bogus")
	}
}

func TestMatchesIPAllowlist(t *testing.T) {
	cases := []struct {
		name      string
		allowlist []string
		callerIP  string
		want      bool
	}{
		{"empty allowlist allows all", nil, "1.2.3.4", true},
		{"exact v4 match", []string{"1.2.3.4"}, "1.2.3.4", true},
		{"v4 miss", []string{"1.2.3.4"}, "1.2.3.5", false},
		{"v4 cidr hit", []string{"10.0.0.0/24"}, "10.0.0.7", true},
		{"v4 cidr miss", []string{"10.0.0.0/24"}, "10.0.1.7", false},
		{"v6 exact match", []string{"2001:db8::1"}, "2001:db8::1", true},
		{"v6 cidr hit", []string{"2001:db8::/32"}, "2001:db8:1:2::abcd", true},
		{"malformed entry skipped, others honoured", []string{"not-an-ip", "1.2.3.4"}, "1.2.3.4", true},
		{"unparsable caller IP rejected", []string{"1.2.3.4"}, "garbage", false},
		{"whitespace-padded entry", []string{" 1.2.3.4 "}, "1.2.3.4", true},
		{"mixed v4 entry vs v6 caller", []string{"10.0.0.0/24"}, "2001:db8::1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchesIPAllowlist(c.allowlist, c.callerIP); got != c.want {
				t.Fatalf("MatchesIPAllowlist(%v, %q) = %v, want %v", c.allowlist, c.callerIP, got, c.want)
			}
		})
	}
}

func TestValidateIPAllowlist(t *testing.T) {
	if got := ValidateIPAllowlist([]string{"1.2.3.4", "10.0.0.0/8", "2001:db8::/32", ""}); got != "" {
		t.Fatalf("ValidateIPAllowlist(valid) = %q, want empty", got)
	}
	if got := ValidateIPAllowlist([]string{"1.2.3.4", "10.0.0.0/40"}); got != "10.0.0.0/40" {
		t.Fatalf("ValidateIPAllowlist(bad cidr) = %q, want %q", got, "10.0.0.0/40")
	}
	if got := ValidateIPAllowlist([]string{"999.1.1.1"}); got != "999.1.1.1" {
		t.Fatalf("ValidateIPAllowlist(bad ip) = %q, want %q", got, "999.1.1.1")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://app.example.com", "https://app.example.com"},
		{"HTTPS://APP.Example.COM", "https://app.example.com"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"https://app.example.com/", "https://app.example.com"},
		{"https://app.example.com/path", ""},
		{"https://app.example.com?q=1", ""},
		{"https://app.example.com#frag", ""},
		{"https://user:pw@app.example.com", ""},
		{"ftp://app.example.com", ""},
		{"", ""},
		{"   ", ""},
		{"not a url at all ::::", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := NormalizeOrigin(c.in); got != c.want {
				t.Fatalf("NormalizeOrigin(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMatchesOriginAllowlist(t *testing.T) {
	cases := []struct {
		name      string
		allowlist []string
		origin    string
		want      bool
	}{
		{"empty allowlist allows all", nil, "https://anything.example.com", true},
		{"no origin header passes (server-to-server)", []string{"https://app.example.com"}, "", true},
		{"unparsable origin passes (not a browser)", []string{"https://app.example.com"}, "garbage", true},
		{"exact match", []string{"https://app.example.com"}, "https://app.example.com", true},
		{"case-insensitive host", []string{"https://app.example.com"}, "https://APP.example.com", true},
		{"scheme mismatch", []string{"https://app.example.com"}, "http://app.example.com", false},
		{"host mismatch", []string{"https://app.example.com"}, "https://evil.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchesOriginAllowlist(c.allowlist, c.origin); got != c.want {
				t.Fatalf("MatchesOriginAllowlist(%v, %q) = %v, want %v", c.allowlist, c.origin, got, c.want)
			}
		})
	}
}

func TestValidateOriginAllowlist(t *testing.T) {
	if got := ValidateOriginAllowlist([]string{"https://a.example.com", "http://localhost:3000", ""}); got != "" {
		t.Fatalf("ValidateOriginAllowlist(valid) = %q, want empty", got)
	}
	if got := ValidateOriginAllowlist([]string{"https://a.example.com", "https://a.example.com/path"}); got != "https://a.example.com/path" {
		t.Fatalf("ValidateOriginAllowlist(bad) = %q", got)
	}
}
