package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// SelfCalibrate verifies the probe engine against a local, in-process TLS server
// whose standard-library stack negotiates X25519MLKEM768. If the engine cannot
// detect PQC on a server that indisputably supports it, its verdicts are not
// trustworthy, so callers should refuse to report. This is hermetic: it needs no
// network and works in any environment.
func SelfCalibrate() error {
	cert, err := selfSignedCert()
	if err != nil {
		return fmt.Errorf("self-calibration setup: %w", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return fmt.Errorf("self-calibration listener: %w", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					tc.SetDeadline(time.Now().Add(3 * time.Second))
					_ = tc.Handshake() // client hangs up after ServerHello; error is expected
				}
			}(c)
		}
	}()

	ok, err := probeGroup(ln.Addr().String(), "pqscan.local", GroupX25519MLKEM768, nil, 3*time.Second)
	if err != nil {
		return fmt.Errorf("self-calibration probe error: %w", err)
	}
	if !ok {
		return errors.New("self-calibration failed: engine did not detect X25519MLKEM768 on a PQC-capable local server")
	}
	return nil
}

func selfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqscan-selftest"},
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
