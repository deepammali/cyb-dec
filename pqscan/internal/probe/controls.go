package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

// Control is one engine calibration: a probe run against a local reference
// server whose answer is known in advance. A positive control that reads
// negative would mean the engine produces false negatives; a negative control
// that reads positive would mean false positives.
type Control struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	Got    string `json:"got"`
	Pass   bool   `json:"pass"`
}

// ControlsPassed reports whether controls ran and every one passed.
func ControlsPassed(cs []Control) bool {
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		if !c.Pass {
			return false
		}
	}
	return true
}

// RunControls probes four in-process reference servers through the same code
// paths real scans use. It is hermetic: loopback only, no external network.
func RunControls() []Control {
	const timeout = 3 * time.Second
	var out []Control

	tlsControl := func(name string, curves []tls.CurveID, wantPQ bool) Control {
		c := Control{Name: name}
		if wantPQ {
			c.Expect = "post-quantum: server chooses X25519MLKEM768 and completes an ML-KEM-only handshake"
		} else {
			c.Expect = "classical: server chooses X25519 and refuses an ML-KEM-only handshake"
		}
		host, port, stop, err := referenceTLSServer(curves)
		if err != nil {
			c.Got = "could not start reference server: " + err.Error()
			return c
		}
		defer stop()
		r := ProbeTLS(name, host, port, "pqscan.local", nil, timeout)
		forced := "not run"
		if r.Forced != nil {
			switch {
			case r.Forced.Completed:
				forced = "completed"
			case r.Forced.Refused:
				forced = "refused"
			}
		}
		c.Got = fmt.Sprintf("server chose %s; ML-KEM-only handshake %s", orNone(r.NegotiatedGroup), forced)
		if r.Error != "" {
			c.Got = "probe failed: " + r.Error
		}
		if wantPQ {
			c.Pass = r.PQKeyExchange && r.NegotiatedGroup == "X25519MLKEM768" && forced == "completed"
		} else {
			c.Pass = r.Reachable && !r.PQKeyExchange && r.NegotiatedGroup == "X25519" && forced == "refused"
		}
		return c
	}
	sshControl := func(name, kex string, wantPQ bool) Control {
		c := Control{Name: name}
		if wantPQ {
			c.Expect = "post-quantum: mlkem768x25519-sha256 detected in KEXINIT"
		} else {
			c.Expect = "classical: no post-quantum method in KEXINIT"
		}
		host, port, stop, err := referenceSSHServer(kex)
		if err != nil {
			c.Got = "could not start reference server: " + err.Error()
			return c
		}
		defer stop()
		r := ProbeSSH(name, host, port, timeout)
		switch {
		case r.Error != "":
			c.Got = "probe failed: " + r.Error
		case r.PQKeyExchange:
			c.Got = "post-quantum: " + r.BestPQGroup
		default:
			c.Got = "classical: " + strings.Join(r.Advertised, ",")
		}
		c.Pass = r.Error == "" && r.PQKeyExchange == wantPQ
		return c
	}

	out = append(out,
		tlsControl("TLS positive control", nil, true),
		tlsControl("TLS negative control", []tls.CurveID{tls.X25519, tls.CurveP256}, false),
		sshControl("SSH positive control", "mlkem768x25519-sha256,curve25519-sha256", true),
		sshControl("SSH negative control", "curve25519-sha256,ecdh-sha2-nistp256", false),
	)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

// referenceTLSServer starts a loopback TLS 1.3 server. curves nil means Go's
// default, which includes X25519MLKEM768.
func referenceTLSServer(curves []tls.CurveID) (string, int, func(), error) {
	cert, err := selfSignedCert()
	if err != nil {
		return "", 0, nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: curves,
	})
	if err != nil {
		return "", 0, nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake() // probes hang up after the ServerHello; errors are expected
				}
			}(c)
		}
	}()
	host, port := hostPort(ln.Addr())
	return host, port, func() { ln.Close() }, nil
}

// referenceSSHServer starts a loopback server that sends an SSH banner and a
// KEXINIT advertising kex.
func referenceSSHServer(kex string) (string, int, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", 0, nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				conn.Write([]byte("SSH-2.0-pqscan_control\r\n"))
				readLine(conn)
				conn.Write(kexinitPacket(kex))
			}(c)
		}
	}()
	host, port := hostPort(ln.Addr())
	return host, port, func() { ln.Close() }, nil
}

// kexinitPacket builds an SSH_MSG_KEXINIT binary packet whose kex_algorithms
// name-list is kex. Only the first two name-lists are filled in; the probe reads
// only kex_algorithms.
func kexinitPacket(kex string) []byte {
	nameList := func(s string) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(s)))
		return append(b, []byte(s)...)
	}
	payload := []byte{20}                          // SSH_MSG_KEXINIT
	payload = append(payload, make([]byte, 16)...) // cookie
	payload = append(payload, nameList(kex)...)
	payload = append(payload, nameList("ssh-ed25519")...)

	padLen := 8 - ((4 + 1 + len(payload)) % 8)
	if padLen < 4 {
		padLen += 8
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(1+len(payload)+padLen))
	out = append(out, byte(padLen))
	out = append(out, payload...)
	return append(out, make([]byte, padLen)...)
}

func hostPort(a net.Addr) (string, int) {
	h, p, _ := net.SplitHostPort(a.String())
	n, _ := strconv.Atoi(p)
	return h, n
}

func selfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqscan-reference"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"pqscan.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
