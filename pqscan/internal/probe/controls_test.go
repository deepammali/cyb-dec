package probe

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"
)

// The four engine controls must pass: they are what rules out systematic false
// positives and false negatives before any real scan is trusted.
func TestControlsPass(t *testing.T) {
	cs := RunControls()
	if len(cs) != 4 {
		t.Fatalf("got %d controls, want 4", len(cs))
	}
	for _, c := range cs {
		if !c.Pass {
			t.Errorf("%s failed: expected %s, got %s", c.Name, c.Expect, c.Got)
		}
	}
	if !ControlsPassed(cs) {
		t.Fatal("ControlsPassed should be true")
	}
	if ControlsPassed(nil) {
		t.Fatal("no controls run must not count as passed")
	}
}

// The forced check is the independent second opinion: it completes against an
// ML-KEM server and is refused by a classical one.
func TestForcedCheck(t *testing.T) {
	for _, tc := range []struct {
		name      string
		curves    []tls.CurveID
		completed bool
	}{
		{"ml-kem server", nil, true},
		{"classical server", []tls.CurveID{tls.X25519, tls.CurveP256}, false},
	} {
		host, port, stop, err := referenceTLSServer(tc.curves)
		if err != nil {
			t.Fatal(err)
		}
		fc := forcedMLKEM(net.JoinHostPort(host, strconv.Itoa(port)), "pqscan.local", nil, 3*time.Second)
		stop()
		if fc.Completed != tc.completed || fc.Refused == tc.completed {
			t.Errorf("%s: forced = %+v", tc.name, fc)
		}
	}
}
