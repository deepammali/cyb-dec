package safety

import (
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com", "example.com", 0},
		{"  Example.COM.  ", "example.com", 0},
		{"example.com:2222", "example.com", 2222},
		{"https://example.com/path?q=1", "example.com", 0},
		{"HTTPS://Example.COM:8443/x", "example.com", 8443},
		{"ssh://admin@bastion.corp.local:22", "bastion.corp.local", 22},
		{"mailhost", "mailhost", 0},
		{"mail.corp.local:587", "mail.corp.local", 587},
		{"10.0.0.5:2222", "10.0.0.5", 2222},
		{"[fd00::5]:8443", "fd00::5", 8443},
		{"[2606:4700::1111]", "2606:4700::1111", 0},
		{"2606:4700::1111", "2606:4700::1111", 0},
	}
	for _, tc := range cases {
		host, port, err := ParseTarget(tc.in)
		if err != nil {
			t.Errorf("ParseTarget(%q) error: %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("ParseTarget(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.host, tc.port)
		}
	}
	for _, bad := range []string{"", "   ", "example.com:0", "example.com:70000", "example.com:ssh", "bad host", "[fd00::5"} {
		if _, _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) should fail", bad)
		}
	}
}

func TestValidatePublicBlocksNonPublicIPs(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1",
		"172.16.0.1", "0.0.0.0", "100.64.0.1", "::1", "fe80::1",
	}
	for _, ip := range blocked {
		if err := ValidatePublic(ip); err == nil {
			t.Errorf("ValidatePublic(%q) should be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if err := ValidatePublic(ip); err != nil {
			t.Errorf("ValidatePublic(%q) should pass, got %v", ip, err)
		}
	}
}

func TestResolve(t *testing.T) {
	if err := Resolve("10.0.0.5"); err != nil {
		t.Errorf("IP literal should resolve: %v", err)
	}
	if err := Resolve("localhost"); err != nil {
		t.Errorf("localhost should resolve: %v", err)
	}
	if err := Resolve("no-such-host.invalid"); err == nil {
		t.Error(".invalid must not resolve")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	if !rl.Allow("a") || !rl.Allow("a") {
		t.Fatal("first two should be allowed")
	}
	if rl.Allow("a") {
		t.Fatal("third should be blocked")
	}
	if !rl.Allow("b") {
		t.Fatal("different key should be allowed")
	}
}
