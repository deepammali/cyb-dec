package probe

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// srvReadLine reads one line (byte-at-a-time) from a server-side connection so no
// bytes past the negotiation are buffered before the TLS upgrade.
func srvReadLine(c net.Conn) string {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := c.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimRight(string(b), "\r\n")
			}
			b = append(b, one[0])
		}
		if err != nil {
			return string(b)
		}
	}
}

func srvReadUntil(c net.Conn, prefix string) {
	for {
		line := srvReadLine(c)
		if line == "" || strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(prefix)) {
			return
		}
	}
}

// serveOnce accepts one connection, runs handle (the STARTTLS dance), then
// upgrades to a TLS server that supports X25519MLKEM768.
func serveOnce(t *testing.T, handle func(net.Conn)) net.Listener {
	t.Helper()
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
				s := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
				})
				_ = s.Handshake() // client reads ServerHello then hangs up
			}(c)
		}
	}()
	return ln
}

func TestSMTPStartTLSHermetic(t *testing.T) {
	ln := serveOnce(t, func(c net.Conn) {
		c.Write([]byte("220 local ESMTP\r\n"))
		srvReadUntil(c, "EHLO")
		c.Write([]byte("250-local\r\n250 STARTTLS\r\n"))
		srvReadUntil(c, "STARTTLS")
		c.Write([]byte("220 go ahead\r\n"))
	})
	defer ln.Close()

	ok, err := probeGroup(ln.Addr().String(), "pqscan.local", GroupX25519MLKEM768, SMTPStartTLS, 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !ok {
		t.Fatal("SMTP STARTTLS server should negotiate X25519MLKEM768")
	}
}

func TestPostgresStartTLSHermetic(t *testing.T) {
	ln := serveOnce(t, func(c net.Conn) {
		req := make([]byte, 8) // read the SSLRequest
		c.Read(req)
		c.Write([]byte{'S'}) // TLS supported
	})
	defer ln.Close()

	ok, err := probeGroup(ln.Addr().String(), "pqscan.local", GroupX25519MLKEM768, PostgresStartTLS, 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !ok {
		t.Fatal("PostgreSQL STARTTLS server should negotiate X25519MLKEM768")
	}
}
