package probe

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DefaultTimeout bounds each probe (dial + handshake round trip).
const DefaultTimeout = 8 * time.Second

// Preamble upgrades a freshly dialed TCP connection to the point where a TLS
// ClientHello is expected (a STARTTLS negotiation) and returns the server's
// greeting line, if it sent one. nil means implicit TLS.
type Preamble func(conn net.Conn, serverName string) (greeting string, err error)

// GroupResult is the outcome of probing a single named group, with the evidence:
// what we offered and what the server picked from that offer.
type GroupResult struct {
	Group         string `json:"group"`
	ID            uint16 `json:"id"`
	Supported     bool   `json:"supported"`
	Offered       string `json:"offered,omitempty"`
	ServerChose   string `json:"serverChose,omitempty"`
	Alerted       bool   `json:"alerted,omitempty"`       // the server refused the whole offer
	LowConfidence bool   `json:"lowConfidence,omitempty"` // legacy group: a negative is not authoritative
	Note          string `json:"note,omitempty"`
}

// ServiceResult is the per-service probe outcome. Kind is "tls" or "ssh"; a few
// fields are populated only for one kind.
type ServiceResult struct {
	Service         string        `json:"service"`
	Kind            string        `json:"kind"`
	Protocol        string        `json:"protocol,omitempty"` // e.g. "tls", "smtp+starttls", "ssh"
	Detected        bool          `json:"detected,omitempty"` // protocol was auto-detected
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	Reachable       bool          `json:"reachable"`
	Banner          string        `json:"banner,omitempty"` // SSH identification or plaintext greeting
	TLSVersion      string        `json:"tlsVersion,omitempty"`
	CipherSuite     string        `json:"cipherSuite,omitempty"`
	ServerCipher    string        `json:"serverCipher,omitempty"` // suite chosen when AES-256 was offered first
	Groups          []GroupResult `json:"groups"`
	Advertised      []string      `json:"advertised,omitempty"` // SSH kex_algorithms
	PQKeyExchange   bool          `json:"pqKeyExchange"`
	BestPQGroup     string        `json:"bestPqGroup,omitempty"`
	NegotiatedGroup string        `json:"negotiatedGroup,omitempty"` // what a modern client (ML-KEM + X25519) gets
	CertSigAlg      string        `json:"certSignatureAlgorithm,omitempty"`
	CertNotAfter    string        `json:"certNotAfter,omitempty"`
	CertSubject     string        `json:"certSubject,omitempty"`
	Address         string        `json:"address,omitempty"`      // the IP:port actually tested
	Forced          *ForcedCheck  `json:"forcedCheck,omitempty"`  // independent second check (TLS)
	OfferSamples    []string      `json:"offerSamples,omitempty"` // server's choice on each repeated offer
	Edge            *Edge         `json:"edge,omitempty"`         // CDN/proxy terminating TLS, if detected
	Error           string        `json:"error,omitempty"`
	ErrorKind       string        `json:"errorKind,omitempty"`
}

// ForcedCheck is the independent confirmation of a TLS result: a full handshake
// with a different TLS implementation (Go crypto/tls) that offers only
// X25519MLKEM768. It completes only if the server really does ML-KEM.
type ForcedCheck struct {
	Group     string `json:"group"`
	Completed bool   `json:"completed"`        // handshake completed with ML-KEM
	Refused   bool   `json:"refused"`          // server rejected an ML-KEM-only offer
	Detail    string `json:"detail,omitempty"` // server's refusal, or why the check couldn't run
}

func (r ServiceResult) fail(err error) ServiceResult {
	r.Error = err.Error()
	r.ErrorKind = ErrorKind(err)
	return r
}

// TLSOptions tune a TLS probe beyond the essentials.
type TLSOptions struct {
	// Samples is how many times the decisive offer (X25519MLKEM768 + X25519) is
	// made. More than one reveals a pool of differently configured servers
	// behind one address.
	Samples int
	// HTTP sends one HEAD request after the handshake to learn whether TLS
	// terminates at a CDN or proxy rather than at the origin.
	HTTP bool
}

// ProbeTLS scans one TLS service at host:port with default options.
func ProbeTLS(service, host string, port int, serverName string, pre Preamble, timeout time.Duration) ServiceResult {
	return ProbeTLSWith(service, host, port, serverName, pre, timeout, TLSOptions{})
}

// ProbeTLSWith scans one TLS service at host:port. host is what gets dialed (a
// name or one of its addresses); serverName is the SNI to present. pre is the
// STARTTLS preamble (nil for implicit TLS). It builds the ML-KEM support matrix
// via hand-crafted ClientHellos and gathers TLS/cert context via a standard
// handshake.
func ProbeTLSWith(service, host string, port int, serverName string, pre Preamble, timeout time.Duration, opts TLSOptions) ServiceResult {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := ServiceResult{Service: service, Kind: "tls", Host: host, Port: port}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// A failed connect or STARTTLS negotiation would fail identically for every
	// group probe, so stop here rather than wait out the timeout again.
	raw, greeting, err := dialWithPreamble(addr, serverName, pre, timeout)
	res.Banner = greeting
	if err != nil {
		return res.fail(err)
	}
	res.Address = raw.RemoteAddr().String()

	// TLS/cert context via a standard handshake (skip verification but keep the cert).
	reachable := false
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
			res.CertNotAfter = c.NotAfter.UTC().Format(time.RFC3339)
			res.CertSubject = c.Subject.CommonName
		}
		if opts.HTTP {
			res.Edge = detectEdge(tconn, serverName, timeout)
		}
	}
	tconn.Close()

	// ML-KEM group support matrix via hand-crafted ClientHellos.
	for i, g := range PQGroups {
		gr := GroupResult{Group: g.Name, ID: g.ID, Offered: g.Name + " + X25519"}
		c, derr := probeGroup(addr, serverName, g.ID, pre, timeout)
		if derr != nil {
			if !reachable {
				return res.fail(derr)
			}
			gr.Note = "probe error: " + derr.Error()
		} else {
			reachable = true
			gr.Supported = c.Found && c.Selected == g.ID
			gr.Alerted = c.Alert
			if c.Found {
				gr.ServerChose = chosenName(c.Selected)
			}
			if i == 0 && c.Found {
				// Our first offer mirrors a current browser (X25519MLKEM768 + X25519).
				res.NegotiatedGroup = gr.ServerChose
				res.ServerCipher = tls.CipherSuiteName(c.Cipher)
			}
		}
		if g.Legacy {
			gr.LowConfidence = true
			if !gr.Supported {
				gr.Note = "legacy draft; negative is not authoritative (Kyber round-3 key not minted)"
			}
		}
		res.Groups = append(res.Groups, gr)
		if gr.Supported && !g.Legacy {
			res.PQKeyExchange = true
			if res.BestPQGroup == "" {
				res.BestPQGroup = g.Name
			}
		} else if gr.Supported && g.Legacy && res.BestPQGroup == "" {
			res.BestPQGroup = g.Name + " (legacy)"
		}
	}
	res.Reachable = reachable
	if len(res.Groups) > 0 && res.Groups[0].Note == "" {
		res.OfferSamples = []string{sampleName(res.Groups[0])}
		for i := 1; i < opts.Samples; i++ {
			c, err := probeGroup(addr, serverName, GroupX25519MLKEM768, pre, timeout)
			switch {
			case err != nil:
				res.OfferSamples = append(res.OfferSamples, "error")
			case c.Alert:
				res.OfferSamples = append(res.OfferSamples, "refused")
			default:
				res.OfferSamples = append(res.OfferSamples, chosenName(c.Selected))
			}
		}
	}
	res.Forced = forcedMLKEM(addr, serverName, pre, timeout)
	return res
}

func sampleName(g GroupResult) string {
	if g.Alerted {
		return "refused"
	}
	return g.ServerChose
}

// forcedMLKEM runs the independent check: a complete Go crypto/tls handshake
// that offers only X25519MLKEM768.
func forcedMLKEM(addr, serverName string, pre Preamble, timeout time.Duration) *ForcedCheck {
	fc := &ForcedCheck{Group: "X25519MLKEM768"}
	raw, _, err := dialWithPreamble(addr, serverName, pre, timeout)
	if err != nil {
		fc.Detail = "could not connect: " + err.Error()
		return fc
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
	})
	c.SetDeadline(time.Now().Add(timeout))
	err = c.Handshake()
	switch {
	case err == nil:
		fc.Completed = true
	case ErrorKind(err) == "timeout":
		fc.Detail = "timed out: " + err.Error()
	default:
		// An alert, a hang-up, or a server choosing something we didn't offer:
		// in every case the server did not complete an ML-KEM handshake.
		fc.Refused = true
		fc.Detail = err.Error()
	}
	return fc
}

func chosenName(id uint16) string {
	if id == 0 {
		return "none (TLS 1.2 handshake)"
	}
	return GroupName(id)
}

// dialWithPreamble opens a TCP connection, applies the STARTTLS preamble if any,
// and returns the connection positioned for a TLS ClientHello plus the server's
// plaintext greeting (empty for implicit TLS).
func dialWithPreamble(addr, serverName string, pre Preamble, timeout time.Duration) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, "", err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if pre == nil {
		return conn, "", nil
	}
	greeting, err := pre(conn, serverName)
	if err != nil {
		conn.Close()
		return nil, greeting, err
	}
	return conn, greeting, nil
}

// probeGroup offers the group under test together with a classical fallback
// (X25519) and returns what the server selected from that offer.
func probeGroup(addr, serverName string, group uint16, pre Preamble, timeout time.Duration) (serverChoice, error) {
	offer := []uint16{group}
	if group != GroupX25519 {
		offer = append(offer, GroupX25519)
	}
	hello, err := buildClientHello(serverName, offer...)
	if err != nil {
		return serverChoice{}, err
	}
	conn, _, err := dialWithPreamble(addr, serverName, pre, timeout)
	if err != nil {
		return serverChoice{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(hello); err != nil {
		return serverChoice{}, err
	}

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var lastErr error
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if c, perr := parseServerResponse(buf); perr == nil && (c.Alert || c.Found) {
				return c, nil
			}
			if len(buf) > 1<<16 {
				break
			}
		}
		if rerr != nil {
			lastErr = rerr
			break
		}
	}
	if c, perr := parseServerResponse(buf); perr == nil && (c.Alert || c.Found) {
		return c, nil
	}
	if len(buf) > 0 {
		return serverChoice{}, errNotTLS
	}
	if lastErr != nil && !errors.Is(lastErr, io.EOF) {
		return serverChoice{}, fmt.Errorf("no TLS response: %w", lastErr)
	}
	return serverChoice{}, errClosedByPeer
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
