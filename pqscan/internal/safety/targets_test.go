package safety

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	in := `
# estate
mail.corp.local
10.0.0.5:2222        # bastion
https://intranet.corp.local:8443/login
10.1.2.0/30
fd00::10/127
mail.corp.local
`
	got, err := ParseTargets(strings.NewReader(in), 50)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, tg := range got {
		hosts = append(hosts, tg.Host)
	}
	want := []string{"mail.corp.local", "10.0.0.5", "intranet.corp.local", "10.1.2.1", "10.1.2.2", "fd00::10", "fd00::11"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	if got[1].Port != 2222 || got[2].Port != 8443 || got[3].Port != 0 {
		t.Fatalf("ports = %d, %d, %d", got[1].Port, got[2].Port, got[3].Port)
	}
}

func TestParseTargetsCaps(t *testing.T) {
	if _, err := ParseTargets(strings.NewReader("10.0.0.0/16"), 256); err == nil || !strings.Contains(err.Error(), "65534") {
		t.Fatalf("a /16 must be refused with its size, got %v", err)
	}
	if _, err := ParseTargets(strings.NewReader("a\nb\nc"), 2); err == nil {
		t.Fatal("more targets than the cap must be refused")
	}
	if _, err := ParseTargets(strings.NewReader("# nothing\n\n"), 10); err == nil {
		t.Fatal("an empty list must be refused")
	}
	if _, err := ParseTargets(strings.NewReader("ok.example\nbad host\n"), 10); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("errors should name the line, got %v", err)
	}
}

func TestResolveAll(t *testing.T) {
	fake := func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "fleet.test" {
			return nil, errors.New("nxdomain")
		}
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"),
		}, nil
	}
	got, err := ResolveAll(context.Background(), fake, "fleet.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("2001:db8::1")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (deduped, IPv4 first)", got, want)
	}
	if capped, _ := ResolveAll(context.Background(), fake, "fleet.test", 2); len(capped) != 2 {
		t.Fatalf("cap not applied: %v", capped)
	}
	if lit, _ := ResolveAll(context.Background(), fake, "192.0.2.7", 0); len(lit) != 1 || lit[0].String() != "192.0.2.7" {
		t.Fatalf("IP literal = %v", lit)
	}
	if _, err := ResolveAll(context.Background(), fake, "missing.test", 0); err == nil {
		t.Fatal("unresolvable name must fail")
	}
}
