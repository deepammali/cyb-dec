package probe

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeFromHeaders(t *testing.T) {
	cases := []struct {
		headers map[string]string
		name    string
	}{
		{map[string]string{"Cf-Ray": "8a1b2c3d-AMS", "Server": "cloudflare"}, "Cloudflare"},
		{map[string]string{"X-Amz-Cf-Id": "abc"}, "Amazon CloudFront"},
		{map[string]string{"Server": "AkamaiGHost"}, "Akamai"},
		{map[string]string{"X-Served-By": "cache-ams21040-AMS"}, "Fastly"},
		{map[string]string{"Server": "envoy"}, "Envoy"},
		{map[string]string{"Via": "1.1 varnish"}, "HTTP proxy"},
		{map[string]string{"Server": "nginx"}, ""},
	}
	for _, tc := range cases {
		h := http.Header{}
		for k, v := range tc.headers {
			h.Set(k, v)
		}
		e := edgeFromHeaders(h)
		switch {
		case tc.name == "" && e != nil:
			t.Errorf("%v: expected no edge, got %+v", tc.headers, e)
		case tc.name != "" && (e == nil || e.Name != tc.name):
			t.Errorf("%v: expected %s, got %+v", tc.headers, tc.name, e)
		}
	}
}

// A real HTTPS server behind a proxy that adds Via must be reported as an edge.
func TestProbeTLSDetectsEdge(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 edge-proxy.corp.local")
	}))
	defer ts.Close()
	host, port := splitHostPort(t, ts.Listener.Addr().String())
	res := ProbeTLSWith("HTTPS", host, port, "example.com", nil, 3*time.Second, TLSOptions{HTTP: true})
	if res.Edge == nil || res.Edge.Kind != "proxy" || res.Edge.Evidence != "via: 1.1 edge-proxy.corp.local" {
		t.Fatalf("edge = %+v", res.Edge)
	}
}

// A pool behind one address that alternates ML-KEM and classical backends must
// show both answers across the repeated offers.
func TestProbeTLSSamplesRevealMixedPool(t *testing.T) {
	pqHost, pqPort, stopPQ, err := referenceTLSServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stopPQ()
	clHost, clPort, stopCl, err := referenceTLSServer([]tls.CurveID{tls.X25519})
	if err != nil {
		t.Fatal(err)
	}
	defer stopCl()
	backends := []string{
		net.JoinHostPort(pqHost, strconv.Itoa(pqPort)),
		net.JoinHostPort(clHost, strconv.Itoa(clPort)),
	}
	var n atomic.Int32
	ln := listenLocal(t, func(c net.Conn) {
		b, err := net.Dial("tcp", backends[n.Add(1)%2])
		if err != nil {
			return
		}
		defer b.Close()
		go io.Copy(b, c)
		io.Copy(c, b)
	})
	host, port := splitHostPort(t, ln.Addr().String())
	res := ProbeTLSWith("TLS", host, port, "pool.test", nil, 3*time.Second, TLSOptions{Samples: 4})
	seen := map[string]bool{}
	for _, s := range res.OfferSamples {
		seen[s] = true
	}
	if len(res.OfferSamples) != 4 || !seen["X25519MLKEM768"] || !seen["X25519"] {
		t.Fatalf("samples = %v; want both answers across 4 offers", res.OfferSamples)
	}
}

func TestClientHelloOmitsSNIForIP(t *testing.T) {
	withName, _ := buildClientHello("example.com", GroupX25519)
	withIP, _ := buildClientHello("10.0.0.5", GroupX25519)
	if len(withIP) >= len(withName) {
		t.Fatalf("IP ClientHello (%d bytes) should be shorter than the SNI one (%d)", len(withIP), len(withName))
	}
}
