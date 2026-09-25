// Package safety parses scan targets and rate-limits requests. Private and
// internal addresses are scanned by default; ValidatePublic is the opt-in refusal
// for deployments exposed to the internet (SSRF defense).
package safety

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// extra blocked CIDRs not covered by netip's built-in predicates.
var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this host"
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),  // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("::/128"),        // unspecified v6 (redundant, explicit)
	netip.MustParsePrefix("fe80::/10"),     // v6 link-local (redundant, explicit)
}

// ParseTarget turns user input (bare host, host:port, [v6]:port, or a URL) into a
// lowercase host and an optional port (0 when none was given).
func ParseTarget(in string) (host string, port int, err error) {
	s := strings.TrimSpace(in)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "//")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 { // drop user:pass@
		s = s[i+1:]
	}
	if s == "" {
		return "", 0, fmt.Errorf("enter a hostname, IP address, or host:port")
	}

	portStr := ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("unclosed '[' in %q", in)
		}
		host, rest := s[1:end], s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", 0, fmt.Errorf("unexpected %q after IPv6 address", rest)
			}
			portStr = rest[1:]
		}
		s = host
	case strings.Count(s, ":") == 1:
		s, portStr, _ = strings.Cut(s, ":")
	}

	s = strings.ToLower(strings.Trim(s, "."))
	if s == "" {
		return "", 0, fmt.Errorf("no host in %q", in)
	}
	if !validHost(s) {
		return "", 0, fmt.Errorf("%q is not a valid hostname or IP address", s)
	}
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("port must be 1–65535, got %q", portStr)
		}
		port = p
	}
	return s, port, nil
}

func validHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

// Resolve reports whether host is an IP literal or resolves via the system
// resolver (DNS, /etc/hosts, and whatever else the platform consults).
func Resolve(host string) error {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if _, err := net.LookupHost(host); err != nil {
		return fmt.Errorf("cannot resolve %q", host)
	}
	return nil
}

// blocked reports whether an address is non-public.
func blocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	ip = ip.Unmap()
	for _, p := range extraBlocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidatePublic rejects a host that is, or resolves to, a non-public address.
// It is used only when the web server runs with --public-only.
func ValidatePublic(host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if blocked(ip) {
			return fmt.Errorf("this server only scans public addresses (--public-only); %s is not public", ip)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q", host)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no addresses for %q", host)
	}
	for _, nip := range ips {
		a, ok := netip.AddrFromSlice(nip)
		if !ok || blocked(a.Unmap()) {
			return fmt.Errorf("this server only scans public addresses (--public-only); %q resolves to %s", host, nip)
		}
	}
	return nil
}

// RateLimiter is a minimal fixed-window per-key limiter for the web endpoint.
type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// Allow reports whether key may proceed, recording the attempt if so.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	kept := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.hits[key] = kept
		return false
	}
	r.hits[key] = append(kept, now)
	return true
}
