package probe

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tlsLn.Close() })
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				c.(*tls.Conn).Handshake()
			}(c)
		}
	}()

	cases := []struct {
		name string
		addr string
		want string
	}{
		{"ssh", listenLocal(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")); time.Sleep(time.Second) }).Addr().String(), "ssh"},
		{"smtp", listenLocal(t, func(c net.Conn) { c.Write([]byte("220 mx ESMTP ready\r\n")); time.Sleep(time.Second) }).Addr().String(), "smtp"},
		{"ftp", listenLocal(t, func(c net.Conn) { c.Write([]byte("220 (vsFTPd 3.0.5)\r\n")); time.Sleep(time.Second) }).Addr().String(), "ftp"},
		{"imap", listenLocal(t, func(c net.Conn) { c.Write([]byte("* OK Dovecot ready.\r\n")); time.Sleep(time.Second) }).Addr().String(), "imap"},
		{"pop3", listenLocal(t, func(c net.Conn) { c.Write([]byte("+OK Dovecot ready.\r\n")); time.Sleep(time.Second) }).Addr().String(), "pop3"},
		{"ambiguous 220 answers EHLO", listenLocal(t, func(c net.Conn) {
			c.Write([]byte("220 ready\r\n"))
			srvReadUntil(c, "EHLO")
			c.Write([]byte("250 ok\r\n"))
		}).Addr().String(), "smtp"},
		{"postgres", listenLocal(t, func(c net.Conn) {
			req := make([]byte, 8)
			c.Read(req)
			c.Write([]byte{'S'})
		}).Addr().String(), "postgres"},
		{"implicit tls", tlsLn.Addr().String(), "tls"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := splitHostPort(t, tc.addr)
			got, _, err := Detect(host, port, 3*time.Second)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Detect = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectClosedPort(t *testing.T) {
	_, _, err := Detect("127.0.0.1", closedPort(t), time.Second)
	if ErrorKind(err) != "refused" {
		t.Fatalf("err = %v (kind %q), want refused", err, ErrorKind(err))
	}
}
