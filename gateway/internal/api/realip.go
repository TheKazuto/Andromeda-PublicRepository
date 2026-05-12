package api

import (
	"net"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// trustedRealIP applies chi's RealIP middleware (which rewrites RemoteAddr
// from X-Forwarded-For / X-Real-IP) ONLY when the connection peer is inside
// one of the configured trusted-proxy CIDRs. Without a trusted proxy in
// front, those headers are attacker-controlled and must be ignored — so an
// empty TRUSTED_PROXY_CIDRS leaves RemoteAddr untouched.
func trustedRealIP(trustedCIDRs []string) func(http.Handler) http.Handler {
	trusted := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, raw := range trustedCIDRs {
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			trusted = append(trusted, cidr)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trusted) == 0 || !remoteIPTrusted(r.RemoteAddr, trusted) {
				next.ServeHTTP(w, r)
				return
			}
			middleware.RealIP(next).ServeHTTP(w, r)
		})
	}
}

func remoteIPTrusted(remoteAddr string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(hostFromAddr(remoteAddr))
	if ip == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// callerIP picks the client IP for IP-allowlist checks. trustedRealIP (wired
// in server.go) rewrites RemoteAddr from X-Forwarded-For when the peer is a
// trusted proxy, so RemoteAddr is the source of truth here.
func callerIP(r *http.Request) string {
	return hostFromAddr(r.RemoteAddr)
}

// hostFromAddr strips ":port" from a "host:port" string, returning the raw
// value when there is no port. Correctly handles IPv6 literals such as
// "[2001:db8::1]:443" and bare "2001:db8::1".
func hostFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
