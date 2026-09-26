package safety

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Resolver looks up every address for a host name.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemResolver uses the platform resolver (DNS, /etc/hosts, and the rest).
func SystemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveAll returns every distinct address for host, IPv4 first, capped at max
// (0 = no cap). An IP literal resolves to itself.
func ResolveAll(ctx context.Context, lookup Resolver, host string, max int) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if lookup == nil {
		lookup = SystemResolver
	}
	found, err := lookup(ctx, host)
	if err != nil || len(found) == 0 {
		return nil, fmt.Errorf("cannot resolve %q", host)
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range found {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Is4() != out[j].Is4() {
			return out[i].Is4()
		}
		return out[i].Less(out[j])
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// Target is one line of a target list, parsed.
type Target struct {
	Input string `json:"input"`
	Host  string `json:"host"`
	Port  int    `json:"port,omitempty"` // 0 = scan the selected services
}

// ParseTargets reads a target list: one host, host:port, URL, or CIDR per line;
// blank lines and #-comments are ignored. CIDRs expand to their host addresses
// (IPv4 network and broadcast addresses excluded). The total is capped at
// maxHosts so a typo like /8 can't turn into millions of probes.
func ParseTargets(r io.Reader, maxHosts int) ([]Target, error) {
	var out []Target
	seen := map[string]bool{}
	add := func(t Target) error {
		key := fmt.Sprintf("%s|%d", t.Host, t.Port)
		if seen[key] {
			return nil
		}
		if maxHosts > 0 && len(out) >= maxHosts {
			return fmt.Errorf("target list exceeds %d hosts; raise the limit (--max-hosts) or narrow the list", maxHosts)
		}
		seen[key] = true
		out = append(out, t)
		return nil
	}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") && !strings.Contains(s, "://") {
			if p, err := netip.ParsePrefix(s); err == nil {
				addrs, err := expandPrefix(p, maxHosts)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line, err)
				}
				for _, a := range addrs {
					if err := add(Target{Input: s, Host: a.String()}); err != nil {
						return nil, err
					}
				}
				continue
			}
		}
		host, port, err := ParseTarget(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if err := add(Target{Input: s, Host: host, Port: port}); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the target list is empty")
	}
	return out, nil
}

func expandPrefix(p netip.Prefix, maxHosts int) ([]netip.Addr, error) {
	p = p.Masked()
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > 20 {
		return nil, fmt.Errorf("%s is too large to expand", p)
	}
	count := 1 << hostBits
	skipEnds := p.Addr().Is4() && hostBits >= 2
	usable := count
	if skipEnds {
		usable -= 2
	}
	if maxHosts > 0 && usable > maxHosts {
		return nil, fmt.Errorf("%s expands to %d hosts, over the limit of %d (raise --max-hosts)", p, usable, maxHosts)
	}
	var out []netip.Addr
	a := p.Addr()
	for i := 0; i < count; i++ {
		if !(skipEnds && (i == 0 || i == count-1)) {
			out = append(out, a)
		}
		a = a.Next()
	}
	return out, nil
}
