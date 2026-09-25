package probe

import (
	"net"
	"testing"
	"time"
)

// A closed port must be reported as refused, and fast: the early bail skips the
// group probes that would each fail the same way.
func TestProbeTLSClosedPortBailsEarly(t *testing.T) {
	port := closedPort(t)
	start := time.Now()
	res := ProbeTLS("HTTPS", "127.0.0.1", port, "127.0.0.1", nil, 5*time.Second)
	if res.ErrorKind != "refused" {
		t.Fatalf("errorKind = %q (err %q), want refused", res.ErrorKind, res.Error)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed-port probe took %v; want < 1s", d)
	}
}

// A listener that accepts but never answers reads as a timeout, not "closed".
func TestProbeTLSSilentIsTimeout(t *testing.T) {
	ln := listenLocal(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	host, port := splitHostPort(t, ln.Addr().String())
	res := ProbeTLS("HTTPS", host, port, host, nil, 500*time.Millisecond)
	if res.ErrorKind != "timeout" {
		t.Fatalf("errorKind = %q (err %q), want timeout", res.ErrorKind, res.Error)
	}
}

// A plaintext service that answers with non-TLS bytes is a protocol error, not a
// "classical" TLS server.
func TestProbeTLSPlaintextIsProtocolError(t *testing.T) {
	ln := listenLocal(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.Read(buf)
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	host, port := splitHostPort(t, ln.Addr().String())
	res := ProbeTLS("HTTPS", host, port, host, nil, 2*time.Second)
	if res.Reachable || res.ErrorKind != "protocol" {
		t.Fatalf("got reachable=%v errorKind=%q (err %q), want protocol error", res.Reachable, res.ErrorKind, res.Error)
	}
}

func TestProbeSSHClosedPort(t *testing.T) {
	res := ProbeSSH("SSH", "127.0.0.1", closedPort(t), 2*time.Second)
	if res.ErrorKind != "refused" {
		t.Fatalf("errorKind = %q, want refused", res.ErrorKind)
	}
}
