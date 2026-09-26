package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"pqscan/internal/report"
	"pqscan/internal/safety"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fleet.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// tlsOn serves TLS on addr (with the given curves; nil = Go default, which
// includes X25519MLKEM768) until the test ends.
func tlsOn(t *testing.T, addr string, curves []tls.CurveID) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{testCert(t)}, CurvePreferences: curves})
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.SetDeadline(time.Now().Add(3 * time.Second)); c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return ln
}

// Two addresses behind one name, one with ML-KEM and one classical, must be
// reported as a mixed fleet with each address's outcome.
func TestScanStreamMixedFleet(t *testing.T) {
	pq := tlsOn(t, "127.0.0.1:0", nil)
	_, port, _ := net.SplitHostPort(pq.Addr().String())
	tlsOn(t, "127.0.0.2:"+port, []tls.CurveID{tls.X25519})

	resolver := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, nil
	}
	p, _ := strconv.Atoi(port)
	svc, _ := ForPort("tls", p)
	hr := ScanStream(context.Background(), "fleet.test", []Service{svc}, Options{Timeout: 3 * time.Second, Resolver: resolver}, report.Env{}, nil)
	if len(hr.Services) != 1 {
		t.Fatalf("want one merged row, got %d", len(hr.Services))
	}
	s := hr.Services[0]
	if s.State != report.StateClassical || s.Assessment.Confidence != report.ConfMixed || len(s.PerAddress) != 2 {
		t.Fatalf("mixed fleet: state %s confidence %s per-address %+v", s.State, s.Assessment.Confidence, s.PerAddress)
	}
	if s.PerAddress[0].State != report.StatePQ || s.PerAddress[1].State != report.StateClassical {
		t.Fatalf("per-address = %+v", s.PerAddress)
	}
	if hr.Verdict != report.NotReady {
		t.Fatalf("host verdict = %s", hr.Verdict)
	}
}

func TestScanEstate(t *testing.T) {
	pq := tlsOn(t, "127.0.0.1:0", nil)
	cl := tlsOn(t, "127.0.0.2:0", []tls.CurveID{tls.X25519})
	targets := []safety.Target{
		{Host: "127.0.0.1", Port: pq.Addr().(*net.TCPAddr).Port},
		{Host: "127.0.0.2", Port: cl.Addr().(*net.TCPAddr).Port},
	}
	var events []string
	er := ScanEstate(context.Background(), targets, nil, "auto", Options{Timeout: 3 * time.Second}, report.Env{}, func(ev EstateEvent) {
		events = append(events, ev.Type)
	})
	if len(er.Hosts) != 2 || er.Summary.HostsReady != 1 || er.Summary.HostsNotReady != 1 || er.Verdict != report.NotReady {
		t.Fatalf("estate = %+v", er.Summary)
	}
	count := map[string]int{}
	for _, e := range events {
		count[e]++
	}
	if count["host-start"] != 2 || count["service"] != 2 || count["host-done"] != 2 {
		t.Fatalf("events = %v", events)
	}
}
