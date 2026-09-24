package safety

import (
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path?q=1": "example.com",
		"HTTP://Example.COM:8443":      "example.com",
		"  cloudflare.com  ":           "cloudflare.com",
		"example.com:443":              "example.com",
		"[2606:4700::1111]:853":        "2606:4700::1111",
	}
	for in, want := range cases {
		got, err := NormalizeHost(in)
		if err != nil {
			t.Errorf("NormalizeHost(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeHost("   "); err == nil {
		t.Error("expected error for blank host")
	}
}

func TestValidateBlocksNonPublicIPs(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1",
		"172.16.0.1", "0.0.0.0", "100.64.0.1", "::1", "fe80::1",
	}
	for _, ip := range blocked {
		if _, err := Validate(ip); err == nil {
			t.Errorf("Validate(%q) should be blocked", ip)
		}
	}
	// Public IP literals must pass (no DNS needed).
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if _, err := Validate(ip); err != nil {
			t.Errorf("Validate(%q) should pass, got %v", ip, err)
		}
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
