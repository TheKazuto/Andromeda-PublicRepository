// Package netguard validates outbound RPC URLs before the broadcast layer
// dials them. The intents-backend talks to RPC endpoints that come from two
// places: operator overrides (trusted) and the LI.FI /chains feed (a third
// party). A poisoned /chains response could point a broadcast at internal
// infrastructure (loopback, the cloud metadata endpoint, a private LAN host),
// so URLs from untrusted sources are range-checked here.
package netguard

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// ValidateURLFormat checks only that raw is a syntactically valid http(s) URL
// with a host. It does NOT range-check the target IP, so loopback/private hosts
// pass — use it for operator-controlled overrides where a local dev node or a
// private RPC provider is a legitimate target.
func ValidateURLFormat(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http(s), got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("URL has no host")
	}
	return nil
}

// ValidateRPCURL is the strict guard for URLs from untrusted sources (the LI.FI
// /chains feed). It enforces ValidateURLFormat and additionally rejects URLs
// whose host is an IP literal in a loopback/private/link-local/metadata range.
// Hostnames are left to DNS at dial time (no resolution on the hot path), so
// only IP literals are range-checked — this stops the obvious poisoning vectors
// without adding latency or a DNS dependency.
func ValidateRPCURL(raw string) error {
	if err := ValidateURLFormat(raw); err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimSpace(raw)) // already validated above
	host := u.Hostname()
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil // not an IP literal — a hostname, allowed
	}
	if isBlockedAddr(addr) {
		return fmt.Errorf("RPC URL host %s is in a blocked range", host)
	}
	return nil
}

// isBlockedAddr reports whether addr falls in a range the service must never
// dial from an untrusted URL. Link-local covers the cloud metadata endpoint
// (169.254.169.254); IsPrivate covers IPv6 unique-local (fc00::/7), which the
// IMDSv2 IPv6 address (fd00:ec2::254) lives in.
func isBlockedAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.IsLoopback() || // 127.0.0.0/8, ::1
		addr.IsPrivate() || // 10/8, 172.16/12, 192.168/16, fc00::/7
		addr.IsLinkLocalUnicast() || // 169.254.0.0/16 (incl. metadata), fe80::/10
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || // 0.0.0.0, ::
		addr.IsMulticast()
}
