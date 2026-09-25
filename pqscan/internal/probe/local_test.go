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
	c, err := probeGroup(addr, "example.com", GroupX25519MLKEM768, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("probe X25519MLKEM768: %v", err)
	}
	if !c.Found || c.Selected != GroupX25519MLKEM768 {
		t.Fatalf("local Go TLS server should negotiate X25519MLKEM768, got %+v", c)
	}

	// Go does not implement the P-256/P-384 ML-KEM hybrids -> it must fall back to
	// the classical X25519 we offered alongside.
	for _, g := range []uint16{GroupSecP256r1MLKEM768, GroupSecP384r1MLKEM1024} {
		c, err := probeGroup(addr, "example.com", g, nil, 5*time.Second)
		if err != nil {
			t.Fatalf("probe %s: %v", GroupName(g), err)
		}
		if !c.Found || c.Selected != GroupX25519 {
			t.Fatalf("probe %s: want server to choose X25519, got %+v", GroupName(g), c)
		}
	}
}

// TestProbeTLSEvidence checks the full service probe records what was offered and
// what the server chose, which is the evidence reports show to auditors.
func TestProbeTLSEvidence(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	host, port := splitHostPort(t, u.Host)

	res := ProbeTLS("HTTPS", host, port, "example.com", nil, 5*time.Second)
	if !res.Reachable || !res.PQKeyExchange {
		t.Fatalf("want reachable PQ result, got %+v", res)
	}
	if res.NegotiatedGroup != "X25519MLKEM768" {
		t.Fatalf("negotiatedGroup = %q, want X25519MLKEM768", res.NegotiatedGroup)
	}
	if res.ServerCipher == "" {
		t.Fatal("serverCipher should record the suite the server picked")
	}
	g := res.Groups[1] // SecP256r1MLKEM768
	if g.Offered != "SecP256r1MLKEM768 + X25519" || g.ServerChose != "X25519" || g.Supported {
		t.Fatalf("SecP256r1MLKEM768 evidence = %+v", g)
	}
}
