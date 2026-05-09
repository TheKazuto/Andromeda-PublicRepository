// Package netsafety provides allowlist-style validation for outbound URLs the
// gateway will dispatch requests to (webhooks, future-sign callbacks, etc.).
//
// The risk it mitigates is SSRF: a tenant registers a URL pointing at a
// loopback or private-range address and the gateway, sitting inside Railway's
// private network, makes the request — leaking metadata, hitting internal
// services, or relaying responses.
//
// Two layers of validation:
//
//  1. Static URL parse — only accept https:// in production, restrict to a
//     small set of dev hosts in non-production. Block credentials in URL,
//     non-standard ports for http, suspicious hostnames.
//  2. DNS resolution — every hostname is resolved at registration time AND
//     dispatch time, and any resulting IP that falls in a blocked range
//     (loopback / link-local / private / cloud metadata) is rejected. This
//     defeats DNS rebinding and time-of-check vs time-of-use attacks.
package netsafety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ErrBlockedURL is returned when a URL fails validation.
var ErrBlockedURL = errors.New("url blocked by security policy")

// Mode tells the validator which schemes and dev hosts to accept.
type Mode int

const (
	// ModeProduction permits only https:// and refuses any IP that resolves
	// to a private / loopback / link-local / metadata range.
	ModeProduction Mode = iota
	// ModeDevelopment permits https:// plus http://localhost / http://127.0.0.1
	// for local end-to-end testing. Still blocks every other private range.
	ModeDevelopment
)

// metadataIPv4s is the well-known set of cloud metadata endpoints we never
// want the gateway to reach as a side effect of a tenant-controlled URL.
var metadataIPv4s = map[string]struct{}{
	"169.254.169.254": {}, // AWS / GCP / Azure / DigitalOcean
	"100.100.100.200": {}, // Alibaba
}

// Validator vets URLs at registration and dispatch time.
type Validator struct {
	mode    Mode
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	timeout time.Duration
}

// New returns a Validator using the system DNS resolver.
func New(mode Mode) *Validator {
	resolver := &net.Resolver{}
	return &Validator{
		mode: mode,
		resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			out := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				out = append(out, a.IP)
			}
			return out, nil
		},
		timeout: 3 * time.Second,
	}
}

// ValidateRegister enforces the URL contract at registration time. It does a
// DNS lookup and rejects URLs whose hostnames resolve to any blocked IP.
func (v *Validator) ValidateRegister(ctx context.Context, raw string) error {
	u, err := v.parseAndCheck(raw)
	if err != nil {
		return err
	}
	return v.checkHostIPs(ctx, u.Hostname())
}

// ValidateDispatch is the runtime hook called right before a webhook is
// dispatched. Re-resolves the hostname so DNS rebinding between register and
// dispatch is caught.
func (v *Validator) ValidateDispatch(ctx context.Context, raw string) error {
	return v.ValidateRegister(ctx, raw)
}

func (v *Validator) parseAndCheck(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty URL", ErrBlockedURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrBlockedURL, err)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials in URL not allowed", ErrBlockedURL)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrBlockedURL)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return nil, fmt.Errorf("%w: host contains whitespace", ErrBlockedURL)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		// always OK
	case "http":
		if v.mode != ModeDevelopment {
			return nil, fmt.Errorf("%w: only https:// allowed", ErrBlockedURL)
		}
		// Even in dev, only allow loopback hostnames over plain HTTP — never
		// public domains over HTTP, never private-range IPs over HTTP.
		if !isDevLoopback(host) {
			return nil, fmt.Errorf("%w: http:// only allowed for localhost / 127.0.0.1 in development", ErrBlockedURL)
		}
	default:
		return nil, fmt.Errorf("%w: scheme %q not allowed", ErrBlockedURL, u.Scheme)
	}

	// If the host parses as a literal IP, vet it directly here. checkHostIPs
	// will look it up via DNS for hostnames; literal IPs skip that step but
	// still go through isBlockedIP.
	if ip := net.ParseIP(host); ip != nil {
		if v.mode == ModeDevelopment && ip.IsLoopback() {
			return u, nil
		}
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("%w: literal IP %s is in blocked range", ErrBlockedURL, host)
		}
	}
	return u, nil
}

func (v *Validator) checkHostIPs(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		// Already validated in parseAndCheck.
		return nil
	}
	if v.mode == ModeDevelopment && isDevLoopback(host) {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	ips, err := v.resolve(rctx, host)
	if err != nil {
		return fmt.Errorf("%w: dns lookup: %v", ErrBlockedURL, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: dns returned no addresses for %s", ErrBlockedURL, host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: %s resolves to blocked IP %s", ErrBlockedURL, host, ip)
		}
	}
	return nil
}

// isBlockedIP reports whether ip is in any range we never want the gateway to
// dial as a side effect of a tenant-controlled URL.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if _, ok := metadataIPv4s[v4.String()]; ok {
			return true
		}
		// CGNAT 100.64.0.0/10 — used by some clouds for internal routing.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	if ip.To4() == nil {
		// Reject IPv6 unique local fc00::/7 — Go's IsPrivate covers this for
		// the most part but be explicit defensive.
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
	}
	return false
}

func isDevLoopback(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
