// Package safety validates scan targets and rate-limits requests. The scanner
// dials whatever host a user supplies, so it must refuse to be pointed at
// loopback, private, link-local, or cloud-metadata addresses (SSRF defense).
package safety

import (
	"fmt"
	"net"
	"net/netip"
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

// NormalizeHost strips any scheme, path, and port from user input and returns a
// bare hostname (or IP literal). It does not resolve or validate reachability.
func NormalizeHost(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", fmt.Errorf("empty host")
	}
	// Drop scheme and anything after the authority.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "//")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.Trim(s, ".")
	if s == "" {
		return "", fmt.Errorf("no host in input")
	}
	// Strip an optional :port (but keep bracketed IPv6 intact).
	if strings.HasPrefix(s, "[") {
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		} else {
			s = strings.Trim(s, "[]")
		}
	} else if strings.Count(s, ":") == 1 {
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
	}
	return strings.ToLower(s), nil
}

// blocked reports whether an address must never be scanned.
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

// Validate normalizes the host, resolves it, and rejects it if any resolved
// address is non-public. It returns the normalized host to scan.
func Validate(in string) (string, error) {
	host, err := NormalizeHost(in)
	if err != nil {
		return "", err
	}

	// Direct IP literal.
	if ip, err := netip.ParseAddr(host); err == nil {
		if blocked(ip) {
			return "", fmt.Errorf("refusing to scan non-public address %s", ip)
		}
		return host, nil
	}

	// Hostname: resolve and require every result to be public (blocks rebinding to internal).
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses for %q", host)
	}
	for _, nip := range ips {
		a, ok := netip.AddrFromSlice(nip)
		if !ok || blocked(a.Unmap()) {
			return "", fmt.Errorf("refusing to scan %q: resolves to non-public address %s", host, nip)
		}
	}
	return host, nil
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
