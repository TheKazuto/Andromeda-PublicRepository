package auth

import (
	"net"
	"net/url"
	"strings"
)

// Scope vocabulary used by the gateway when enforcing API key access.
// Backend admin endpoints reuse the exact same names so keys minted by
// /admin/api-keys here flow through the gateway unchanged.
const (
	ScopeRead     = "read"
	ScopeWrite    = "write"
	ScopeAdmin    = "admin"
	ScopeWildcard = "*"
)

// DefaultScopes is what handleAdminCreateKey assigns when the admin
// passes nil/empty scopes. Read+write covers the standard developer
// workflow without leaking access to admin endpoints.
var DefaultScopes = []string{ScopeRead, ScopeWrite}

// ValidateScopes returns "" if every entry is a known scope (or the
// wildcard), else the first invalid entry.
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

// ValidateIPAllowlist returns "" if every entry parses as an IP or
// CIDR, else the first invalid entry.
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
// origin. Trailing slashes, paths, queries and fragments are rejected — an
// origin must not carry any of those.
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

// MatchesOriginAllowlist returns true when the request's Origin header
// matches any entry in the allowlist. An empty allowlist means "no
// restriction" — any origin is accepted (including no Origin at all,
// which is the case for server-to-server calls).
func MatchesOriginAllowlist(allowlist []string, requestOrigin string) bool {
	if len(allowlist) == 0 {
		return true
	}
	requestOrigin = NormalizeOrigin(requestOrigin)
	if requestOrigin == "" {
		// Allowlist is set but the request has no parsable Origin header
		// (likely a server-side caller). The Origin guard is a *browser*
		// defense — server callers are unaffected.
		return true
	}
	for _, entry := range allowlist {
		if NormalizeOrigin(entry) == requestOrigin {
			return true
		}
	}
	return false
}
