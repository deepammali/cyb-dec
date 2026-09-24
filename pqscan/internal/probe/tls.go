package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DefaultTimeout bounds each probe (dial + handshake round trip).
const DefaultTimeout = 8 * time.Second

// GroupResult is the outcome of probing a single named group.
type GroupResult struct {
	Group         string `json:"group"`
	ID            uint16 `json:"id"`
	Supported     bool   `json:"supported"`
	LowConfidence bool   `json:"lowConfidence,omitempty"` // legacy group: a negative is not authoritative
	Note          string `json:"note,omitempty"`
}

// ServiceResult is the per-service readiness report.
type ServiceResult struct {
	Service       string        `json:"service"`
	Host          string        `json:"host"`
	Port          int           `json:"port"`
	Reachable     bool          `json:"reachable"`
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

// ProbeTLS scans one implicit-TLS service (e.g. HTTPS) at host:port. serverName is
// the SNI to present (usually host). It builds the ML-KEM support matrix via
// hand-crafted ClientHellos and gathers TLS/cert context via a standard dial.
func ProbeTLS(service, host string, port int, serverName string, timeout time.Duration) ServiceResult {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := ServiceResult{Service: service, Host: host, Port: port}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// TLS/cert context via a standard dial (we scan, so skip verification but keep the cert).
	reachable := false
	dialer := &net.Dialer{Timeout: timeout}
	tconn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err == nil {
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
		tconn.Close()
	}

	// ML-KEM group support matrix via hand-crafted ClientHellos.
	for _, g := range PQGroups {
		gr := GroupResult{Group: g.Name, ID: g.ID}
		supported, derr := probeGroup(addr, serverName, g.ID, timeout)
		if derr != nil {
			if !reachable {
				// Never connected at all: undetermined for the whole service.
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

// probeGroup offers the group under test together with a classical fallback
// (X25519) and reports whether the server selected the tested group. Selecting the
// fallback (or any other group) means the server would not use this PQC group.
func probeGroup(addr, serverName string, group uint16, timeout time.Duration) (bool, error) {
	offer := []uint16{group}
	if group != GroupX25519 {
		offer = append(offer, GroupX25519)
	}
	hello, err := buildClientHello(serverName, offer...)
	if err != nil {
		return false, err
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
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
					return false, nil // handshake_failure: group not supported
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
	// Best effort on whatever we got.
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
