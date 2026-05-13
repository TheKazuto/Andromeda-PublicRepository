package auth

import (
	"net"
	"net/url"
	"strings"
)

// Scope constants. Keep this list short and meaningful — every new
// scope is a permission boundary the operator has to reason about.
const (
	// ScopeRead grants access to T1 (read-class) routes: GETs, polls,
	// status, recovery challenge/preview, ciphertext read, NEK current.
	ScopeRead = "read"
	// ScopeWrite grants access to T2-T5 (tx-class) routes: prepares,
	// submits, signing, recovery quórum/policy mutations.
	ScopeWrite = "write"
	// ScopeAdmin gates feature-management endpoints: webhooks, audit
	// log, policy templates, future-sign triggers. The customer needs
	// to opt in explicitly to mint keys with admin scope.
	ScopeAdmin = "admin"
	// ScopeWildcard grants every other scope. Default for keys created
	// without an explicit scopes argument (back-compat).
	ScopeWildcard = "*"
)

// AllScopes lists every scope the gateway honours. Useful for UI
// dropdowns and bootstrap defaults.
var AllScopes = []string{ScopeRead, ScopeWrite, ScopeAdmin}

// DefaultScopes is what handleAdminCreateKey assigns when the admin
// passes nil/empty scopes. Read+write covers the standard developer
// workflow without leaking access to admin endpoints.
var DefaultScopes = []string{ScopeRead, ScopeWrite}

// HasScope reports whether `granted` covers the `required` scope.
// Wildcard ("*") in granted always returns true. An empty granted
// slice is treated as wildcard for back-compat with keys created
// before scope enforcement existed.
func HasScope(granted []string, required string) bool {
	if len(granted) == 0 {
		return true
	}
	for _, g := range granted {
		if g == ScopeWildcard || g == required {
			return true
		}
	}
	return false
}

// ValidateScopes returns nil if every entry in `scopes` is a known
// scope (or the wildcard), else returns the first invalid entry.
// Used by the admin update endpoint to refuse typos at write time.
func ValidateScopes(scopes []string) string {
	for _, s := range scopes {
		switch s {
		case ScopeRead, ScopeWrite, ScopeAdmin, ScopeWildcard:
		default:
			return s
		}
	}
	return ""
}

// MatchesIPAllowlist returns true when the caller's IP matches any
// entry in the allowlist. An empty allowlist always returns true (no
// restriction). Entries can be plain IPs ("192.168.1.5") or CIDRs
// ("10.0.0.0/24"). Malformed entries are skipped silently — they're
// validated at write time so callers shouldn't see them at runtime.
func MatchesIPAllowlist(allowlist []string, callerIP string) bool {
	if len(allowlist) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(callerIP))
	if ip == nil {
		return false
	}
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return true
			}
		} else {
			parsed := net.ParseIP(entry)
			if parsed != nil && parsed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// ValidateIPAllowlist returns nil if every entry parses as an IP or
// CIDR, else returns the first invalid entry.
func ValidateIPAllowlist(allowlist []string) string {
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return entry
			}
		} else {
			if net.ParseIP(entry) == nil {
				return entry
			}
		}
	}
	return ""
}

// NormalizeOrigin returns the canonical form `scheme://host[:port]` for an
// origin entry, or an empty string if the input does not parse as a valid
// origin. Trailing slashes, paths, queries and fragments are rejected.
func NormalizeOrigin(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	u, err := url.Parse(entry)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	if u.Path != "" && u.Path != "/" {
		return ""
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ""
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

// ValidateOriginAllowlist returns "" if every entry parses as a valid origin
// (scheme://host[:port], no path/query/fragment), else the first invalid
// entry. Wildcards are not accepted.
func ValidateOriginAllowlist(allowlist []string) string {
	for _, entry := range allowlist {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if NormalizeOrigin(entry) == "" {
			return entry
		}
	}
	return ""
}

// MatchesOriginAllowlist returns true when the request's Origin header matches
// any entry in the allowlist. An empty allowlist means "no restriction" (any
// origin accepted, including no Origin at all). When the allowlist is set but
// the request has no parsable Origin, the call is allowed through — the Origin
// guard is a *browser* defense, not a server-to-server one.
func MatchesOriginAllowlist(allowlist []string, requestOrigin string) bool {
	if len(allowlist) == 0 {
		return true
	}
	requestOrigin = NormalizeOrigin(requestOrigin)
	if requestOrigin == "" {
		return true
	}
	for _, entry := range allowlist {
		if NormalizeOrigin(entry) == requestOrigin {
			return true
		}
	}
	return false
}
