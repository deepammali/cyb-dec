package probe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestProbeAgainstLocalPQServer is the hermetic calibration: a local Go TLS
// server (whose stdlib supports X25519MLKEM768) must be detected as supporting the
// hybrid group and as not supporting the groups Go does not implement. This proves
// the hand-crafted ClientHello and ServerHello parser are correct without needing
// external network (which in some environments does not carry PQC handshakes).
func TestProbeAgainstLocalPQServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	addr := u.Host // 127.0.0.1:port

	// Go's TLS server supports X25519MLKEM768 -> must be detected.
	ok, err := probeGroup(addr, "example.com", GroupX25519MLKEM768, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("probe X25519MLKEM768: %v", err)
	}
	if !ok {
		t.Fatal("local Go TLS server should negotiate X25519MLKEM768")
	}

	// Go does not implement the P-256/P-384 ML-KEM hybrids -> must read as not supported.
	for _, g := range []uint16{GroupSecP256r1MLKEM768, GroupSecP384r1MLKEM1024} {
		ok, err := probeGroup(addr, "example.com", g, nil, 5*time.Second)
		if err != nil {
			t.Fatalf("probe %s: %v", GroupName(g), err)
		}
		if ok {
			t.Fatalf("local Go server should not support %s", GroupName(g))
		}
	}
}
