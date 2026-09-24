package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DefaultTimeout bounds each probe (dial + handshake round trip).
const DefaultTimeout = 8 * time.Second

// Preamble upgrades a freshly dialed TCP connection to the point where a TLS
// ClientHello is expected (a STARTTLS negotiation). nil means implicit TLS: the
// TLS handshake begins immediately on connect.
type Preamble func(conn net.Conn, serverName string) error

// GroupResult is the outcome of probing a single named group.
type GroupResult struct {
	Group         string `json:"group"`
	ID            uint16 `json:"id"`
	Supported     bool   `json:"supported"`
	LowConfidence bool   `json:"lowConfidence,omitempty"` // legacy group: a negative is not authoritative
	Note          string `json:"note,omitempty"`
}

// ServiceResult is the per-service readiness report. Kind is "tls" (default) or
// "ssh"; a few fields are populated only for one kind.
type ServiceResult struct {
	Service       string        `json:"service"`
	Kind          string        `json:"kind,omitempty"` // "tls" (default) or "ssh"
	Host          string        `json:"host"`
	Port          int           `json:"port"`
	Reachable     bool          `json:"reachable"`
	Banner        string        `json:"banner,omitempty"` // SSH server identification string
	TLSVersion    string        `json:"tlsVersion,omitempty"`
	CipherSuite   string        `json:"cipherSuite,omitempty"`
	Groups        []GroupResult `json:"groups"`
	PQKeyExchange bool          `json:"pqKeyExchange"`
	BestPQGroup   string        `json:"bestPqGroup,omitempty"`
	CertSigAlg    string        `json:"certSignatureAlgorithm,omitempty"`
	CertNotAfter  string        `json:"certNotAfter,omitempty"`
	CertSubject   string        `json:"certSubject,omitempty"`
	Error         string        `json:"error,omitempty"` // set when a service is undetermined
}

// ProbeTLS scans one TLS service at host:port. serverName is the SNI to present
// (usually host). pre is the STARTTLS preamble (nil for implicit TLS). It builds
// the ML-KEM support matrix via hand-crafted ClientHellos and gathers TLS/cert
// context via a standard handshake.
func ProbeTLS(service, host string, port int, serverName string, pre Preamble, timeout time.Duration) ServiceResult {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := ServiceResult{Service: service, Host: host, Port: port}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// TLS/cert context via a standard handshake (skip verification but keep the cert).
	reachable := false
	if raw, err := dialWithPreamble(addr, serverName, pre, timeout); err == nil {
		tconn := tls.Client(raw, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		tconn.SetDeadline(time.Now().Add(timeout))
		if err := tconn.Handshake(); err == nil {
			reachable = true
			st := tconn.ConnectionState()
			res.TLSVersion = tlsVersionName(st.Version)
			res.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
			if len(st.PeerCertificates) > 0 {
				c := st.PeerCertificates[0]
				res.CertSigAlg = c.SignatureAlgorithm.String()
				res.CertNotAfter = c.NotAfter.UTC().Format("2006-01-02")
				res.CertSubject = c.Subject.CommonName
			}
		}
		tconn.Close()
	}

	// ML-KEM group support matrix via hand-crafted ClientHellos.
	for _, g := range PQGroups {
		gr := GroupResult{Group: g.Name, ID: g.ID}
		supported, derr := probeGroup(addr, serverName, g.ID, pre, timeout)
		if derr != nil {
			if !reachable {
				res.Error = derr.Error()
				return res
			}
			gr.Note = "probe error: " + derr.Error()
		} else {
			gr.Supported = supported
			reachable = true
		}
		if g.Legacy {
			gr.LowConfidence = true
			if !supported {
				gr.Note = "legacy draft; negative is not authoritative (Kyber round-3 key not minted)"
			}
		}
		res.Groups = append(res.Groups, gr)
		if supported && !g.Legacy {
			res.PQKeyExchange = true
			if res.BestPQGroup == "" {
				res.BestPQGroup = g.Name
			}
		} else if supported && g.Legacy && res.BestPQGroup == "" {
			res.BestPQGroup = g.Name + " (legacy)"
		}
	}
	res.Reachable = reachable
	if !reachable && res.Error == "" {
		res.Error = "no TLS response"
	}
	return res
}

// dialWithPreamble opens a TCP connection, applies the STARTTLS preamble if any,
// and returns the connection positioned for a TLS ClientHello.
func dialWithPreamble(addr, serverName string, pre Preamble, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if pre != nil {
		if err := pre(conn, serverName); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// probeGroup offers the group under test together with a classical fallback
// (X25519) and reports whether the server selected the tested group.
func probeGroup(addr, serverName string, group uint16, pre Preamble, timeout time.Duration) (bool, error) {
	offer := []uint16{group}
	if group != GroupX25519 {
		offer = append(offer, GroupX25519)
	}
	hello, err := buildClientHello(serverName, offer...)
	if err != nil {
		return false, err
	}
	conn, err := dialWithPreamble(addr, serverName, pre, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(hello); err != nil {
		return false, err
	}

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if c, perr := parseServerResponse(buf); perr == nil {
				if c.Alert {
					return false, nil
				}
				if c.Found {
					return c.Selected == group, nil
				}
			}
			if len(buf) > 1<<16 {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if c, perr := parseServerResponse(buf); perr == nil {
		if c.Alert {
			return false, nil
		}
		if c.Found {
			return c.Selected == group, nil
		}
	}
	if len(buf) == 0 {
		return false, fmt.Errorf("no response from %s", addr)
	}
	return false, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}
