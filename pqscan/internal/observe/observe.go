package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"pqscan/internal/inspect"
)

// Options control an analysis.
type Options struct {
	KeyLog    *KeyLog // optional: TLS 1.3 secrets for decrypting sessions
	StreamCap int     // bytes reassembled per TCP direction (default 8 MiB)
}

const DefaultStreamCap = 8 << 20

// Analyzer accumulates packets from one or more captures.
type Analyzer struct {
	ctx      context.Context
	opts     Options
	t        *table
	packets  int
	ignored  int // frames that weren't TCP or UDP over IP
	captures int
	first    time.Time
	last     time.Time
}

// New returns an analyzer.
func New(ctx context.Context, o Options) *Analyzer {
	if o.StreamCap <= 0 {
		o.StreamCap = DefaultStreamCap
	}
	return &Analyzer{ctx: ctx, opts: o, t: newTable(o.StreamCap)}
}

// SetKeyLog supplies TLS secrets (for callers that receive them after the capture).
func (a *Analyzer) SetKeyLog(k *KeyLog) { a.opts.KeyLog = k }

// Add reads one capture (pcap or pcapng) to the end.
func (a *Analyzer) Add(r io.Reader) error {
	rd, err := newReader(r)
	if err != nil {
		return err
	}
	a.captures++
	for {
		if a.ctx.Err() != nil {
			return a.ctx.Err()
		}
		frame, link, ts, err := rd.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		a.packets++
		p, ok := decode(frame, link, ts)
		if !ok {
			a.ignored++
			continue
		}
		if !ts.IsZero() {
			if a.first.IsZero() || ts.Before(a.first) {
				a.first = ts
			}
			if ts.After(a.last) {
				a.last = ts
			}
		}
		a.t.add(p)
	}
}

// Report analyzes every flow seen so far.
func (a *Analyzer) Report() Report {
	r := Report{Packets: a.packets, Captures: a.captures, First: a.first, Last: a.last}
	var conns []Connection
	for _, f := range a.t.sorted() {
		var c []Connection
		switch f.proto {
		case 6:
			c = a.tcp(f)
			if len(c) == 0 {
				r.Unanalyzed++
			}
		case 17:
			c = a.udp(f)
		}
		conns = append(conns, c...)
	}
	if a.opts.KeyLog != nil {
		r.KeyLog = &KeyLogUse{Sessions: a.opts.KeyLog.Sessions(), TLS12Lines: a.opts.KeyLog.TLS12}
		for _, c := range conns {
			switch {
			case c.Decryption == "decrypted":
				r.KeyLog.Decrypted++
			case c.Decryption != "":
				r.KeyLog.NotDecrypted++
			}
		}
	}
	return summarize(r, conns)
}

func proto(f *flow) string { return map[uint8]string{6: "tcp", 17: "udp"}[f.proto] }

// tcp analyzes one TCP connection.
func (a *Analyzer) tcp(f *flow) []Connection {
	if !f.sawSYN { // capture began mid-connection: the ClientHello or the lower port decides
		a1, b1 := f.key.a, f.key.b
		switch {
		case f.streams[a1] != nil && findHello(f.streams[a1].data, 1) == 0:
			f.client = a1
		case f.streams[b1] != nil && findHello(f.streams[b1].data, 1) == 0:
			f.client = b1
		case a1.port < b1.port:
			f.client = b1
		default:
			f.client = a1
		}
	}
	c, s, server := f.directions()
	base := Connection{Client: f.client.String(), ClientIP: f.client.addr.String(), Server: server.String(), Count: 1, First: f.first, Last: f.last}
	if st := f.streams[f.client]; st != nil && (st.gap || st.truncated) {
		base.Limits = "Part of the client's stream is missing from the capture or beyond the reassembly limit."
	}
	if i := findHello(c, 1); i >= 0 {
		return []Connection{a.tlsConn(base, c[i:], s, c[:i])}
	}
	if cs, ok := parseSSH(c); ok {
		ss, _ := parseSSH(s)
		return []Connection{sshConn(base, cs, ss)}
	}
	if p := plaintextProtocol(c, s, server.port); p != "" {
		return []Connection{plainConn(base, p, c, s)}
	}
	return nil
}

func preambleProtocol(pre []byte) string {
	up := strings.ToUpper(string(pre))
	switch {
	case len(pre) == 0:
		return "TLS"
	case strings.Contains(up, "STARTTLS"):
		if strings.Contains(up, "EHLO") || strings.Contains(up, "HELO") {
			return "SMTP STARTTLS"
		}
		return "IMAP STARTTLS"
	case strings.Contains(up, "STLS"):
		return "POP3 STARTTLS"
	case strings.Contains(up, "AUTH TLS"):
		return "FTP AUTH TLS"
	case len(pre) == 8 && pre[3] == 8 && pre[4] == 0x04 && pre[5] == 0xd2:
		return "PostgreSQL TLS"
	}
	return "TLS (after a plaintext preamble)"
}

func (a *Analyzer) tlsConn(c Connection, client, server, pre []byte) Connection {
	c.Protocol = preambleProtocol(pre)
	cs := plaintextSide(client, true)
	if len(cs.hellos) == 0 {
		c.Class, c.Outcome = ClassUnknown, "incomplete"
		c.Headline = "The ClientHello couldn't be read from the capture."
		return c
	}
	ch := cs.hellos[0]
	c.ServerName = ch.sni
	c.ClientOffersPQ = anyPQ(ch.groups) || anyPQ(ch.shares)
	c.Offered = groupList(ch.groups)
	c.fact("Client offered groups", groupList(ch.groups))
	c.fact("Client key shares", groupList(ch.shares))
	if len(ch.versions) > 0 {
		var vs []string
		for _, v := range ch.versions {
			vs = append(vs, versionName(v))
		}
		c.fact("Client versions", strings.Join(vs, ", "))
	}
	c.fact("Server name (SNI)", ch.sni)
	c.fact("ALPN", strings.Join(ch.alpn, ", "))
	var ss tlsSide
	if j := findHello(server, 2); j >= 0 {
		ss = plaintextSide(server[j:], false)
	}
	var sh, hrr *hello
	for i := range ss.hellos {
		h := &ss.hellos[i]
		if h.hrr {
			hrr = h
		} else {
			sh = h
		}
	}
	if sh == nil {
		c.Class, c.Outcome = ClassUnknown, "incomplete"
		c.KeyExchange = "—"
		c.Headline = "The server's reply isn't in the capture, so the negotiated key exchange is unknown."
		if c.ClientOffersPQ {
			c.Headline += " The client did offer ML-KEM."
		} else {
			c.Headline += " The client didn't offer ML-KEM, so this connection can't have been post-quantum."
			c.Class, c.Outcome = ClassClassical, "client-classical"
		}
		return c
	}
	version := sh.legacyVer
	if sh.selVersion != 0 {
		version = sh.selVersion
	}
	c.Version = versionName(version)
	c.Cipher = suiteName(sh.suites[0])
	c.fact("Negotiated", c.Version+" · "+c.Cipher)
	if hrr != nil {
		c.fact("HelloRetryRequest", "server asked for "+groupName(hrr.selGroup))
	}
	switch {
	case version == 0x0304:
		c.KeyExchange = groupName(sh.selGroup)
		c.fact("Server chose", c.KeyExchange)
		switch {
		case pqGroup(sh.selGroup):
			c.Class, c.Outcome = ClassPQ, "pq"
			c.Headline = fmt.Sprintf("Negotiated %s: post-quantum key exchange.", c.KeyExchange)
		case c.ClientOffersPQ:
			c.Class, c.Outcome = ClassClassical, "server-classical"
			c.Headline = fmt.Sprintf("The client offered ML-KEM, but the server chose %s: classical key exchange. Fix the server.", c.KeyExchange)
		default:
			c.Class, c.Outcome = ClassClassical, "client-classical"
			c.Headline = fmt.Sprintf("The client didn't offer ML-KEM, so the connection used %s: classical key exchange. Fix the client.", c.KeyExchange)
		}
	default:
		kx, static := tls12KeyExchange(sh.suites[0], ss.ske)
		c.KeyExchange = kx
		c.fact("Key exchange", kx)
		c.Class = ClassClassical
		switch {
		case static:
			c.Outcome = "static-rsa"
			c.Headline = "TLS 1.2 with RSA key transport: no forward secrecy. Whoever obtains the server's private key, by quantum computer or by theft, can decrypt every recorded session."
		case c.ClientOffersPQ:
			c.Outcome = "tls12"
			c.Headline = fmt.Sprintf("The client offered TLS 1.3 with ML-KEM, but the server negotiated %s with %s: classical key exchange. Fix the server.", c.Version, kx)
		default:
			c.Outcome = "tls12"
			c.Headline = fmt.Sprintf("%s with %s: classical key exchange. ML-KEM requires TLS 1.3.", c.Version, kx)
		}
		if len(ss.certs) > 0 {
			c.fact("Server certificate", certSummary(ss.certs[0]))
		}
	}
	if version == 0x0304 && a.opts.KeyLog != nil {
		a.decrypt(&c, ch, sh, cs, ss)
	}
	return c
}

func anyPQ(ids []uint16) bool {
	for _, id := range ids {
		if pqGroup(id) {
			return true
		}
	}
	return false
}

// certSummary describes a DER certificate with the at-rest inspector.
func certSummary(der []byte) string {
	in := inspect.New(context.Background(), inspect.Options{}, nil)
	in.Bytes("certificate", der)
	if r := in.Report(); len(r.Findings) > 0 {
		return r.Findings[0].Protection
	}
	return "unreadable"
}

// decrypt opens a TLS 1.3 session with the key log and inspects what it carried.
func (a *Analyzer) decrypt(c *Connection, ch hello, sh *hello, cs, ss tlsSide) {
	suite, ok := suites13[sh.suites[0]]
	if !ok {
		c.Decryption = "not decrypted: " + c.Cipher + " isn't supported by this build"
		if sh.suites[0] == 0x1303 {
			c.Decryption = "not decrypted: TLS_CHACHA20_POLY1305_SHA256 needs golang.org/x/crypto, which this build doesn't include"
		}
		return
	}
	k := a.opts.KeyLog
	if k.get(ch.random, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == nil {
		c.Decryption = "not decrypted: the key log has no entry for this session"
		return
	}
	sd := decrypt13(ss.recs[ss.encStart:], suite, k.get(ch.random, "SERVER_HANDSHAKE_TRAFFIC_SECRET"), k.get(ch.random, "SERVER_TRAFFIC_SECRET_0"), a.opts.StreamCap)
	cd := decrypt13(cs.recs[cs.encStart:], suite, k.get(ch.random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"), k.get(ch.random, "CLIENT_TRAFFIC_SECRET_0"), a.opts.StreamCap)
	if sd.err != nil {
		c.Decryption = "not decrypted: " + sd.err.Error()
		return
	}
	c.Decryption = "decrypted"
	for _, m := range sd.handshake {
		switch m[0][0] {
		case 11:
			if certs := certList(m[1], true); len(certs) > 0 {
				c.fact("Server certificate", certSummary(certs[0]))
			}
		case 15:
			if len(m[1]) >= 2 {
				id := uint16(m[1][0])<<8 | uint16(m[1][1])
				name := sigSchemes[id]
				if name == "" {
					name = fmt.Sprintf("0x%04X", id)
				}
				c.fact("Server signature", name)
			}
		}
	}
	c.fact("Decrypted", fmt.Sprintf("%d bytes client→server, %d bytes server→client", len(cd.app), len(sd.app)))
	c.inspect(cd.app, "client→server")
	c.inspect(sd.app, "server→client")
}

// inspect runs the at-rest detectors over application bytes carried by a connection.
func (c *Connection) inspect(data []byte, dir string) {
	if len(data) == 0 {
		return
	}
	in := inspect.New(context.Background(), inspect.Options{}, nil)
	where := fmt.Sprintf("%s %s → %s (%s)", c.Protocol, c.Client, c.Server, dir)
	for _, p := range payloadParts(data) {
		label := where
		if p.label != "" {
			label += " " + p.label
		}
		in.Bytes(label, p.data)
	}
	c.Findings = append(c.Findings, in.Report().Findings...)
}

func sshConn(c Connection, cs, ss sshSide) Connection {
	c.Protocol = "SSH"
	c.fact("Client", cs.banner)
	c.fact("Server", ss.banner)
	c.fact("Client key exchange methods", strings.Join(cs.kex, ", "))
	c.fact("Server key exchange methods", strings.Join(ss.kex, ", "))
	c.Offered = strings.Join(cs.kex, ", ")
	for _, k := range cs.kex {
		c.ClientOffersPQ = c.ClientOffersPQ || isSSHPQ(k)
	}
	serverPQ := false
	for _, k := range ss.kex {
		serverPQ = serverPQ || isSSHPQ(k)
	}
	if len(cs.kex) == 0 || len(ss.kex) == 0 {
		c.Class, c.Outcome, c.KeyExchange = ClassUnknown, "incomplete", "—"
		c.Headline = "Only one side's key exchange list is in the capture."
		return c
	}
	c.KeyExchange = firstCommon(cs.kex, ss.kex)
	if hk := firstCommon(cs.hostKeys, ss.hostKeys); hk != "" {
		c.fact("Host key algorithm", hk)
	}
	c.fact("Negotiated", c.KeyExchange)
	switch {
	case isSSHPQ(c.KeyExchange):
		c.Class, c.Outcome = ClassPQ, "pq"
		c.Headline = fmt.Sprintf("Negotiated %s: post-quantum key exchange.", c.KeyExchange)
	case c.ClientOffersPQ && !serverPQ:
		c.Class, c.Outcome = ClassClassical, "server-classical"
		c.Headline = fmt.Sprintf("The client offered post-quantum methods, but the server lists none and %s was used. Fix the server.", c.KeyExchange)
	case serverPQ && !c.ClientOffersPQ:
		c.Class, c.Outcome = ClassClassical, "client-classical"
		c.Headline = fmt.Sprintf("The server supports post-quantum methods, but the client offered none, so %s was used. Fix the client.", c.KeyExchange)
	case serverPQ && c.ClientOffersPQ:
		c.Class, c.Outcome = ClassClassical, "client-classical"
		c.Headline = fmt.Sprintf("Both sides support a post-quantum method, but the client lists %s first, and SSH follows the client's order. Fix the client's KexAlgorithms.", c.KeyExchange)
	default:
		c.Class, c.Outcome = ClassClassical, "classical"
		c.Headline = fmt.Sprintf("Neither side offered a post-quantum method; %s was used.", c.KeyExchange)
	}
	return c
}

func isSSHPQ(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "mlkem") || strings.Contains(k, "sntrup") || strings.Contains(k, "kyber")
}

func plainConn(c Connection, p string, client, server []byte) Connection {
	c.Protocol = p
	c.Class, c.Outcome, c.KeyExchange = ClassPlaintext, "plaintext", "none (plaintext)"
	c.Headline = p + " without TLS: anyone on the path can read it today, no quantum computer needed."
	c.fact("Bytes", fmt.Sprintf("%d client→server, %d server→client", len(client), len(server)))
	c.inspect(client, "client→server")
	c.inspect(server, "server→client")
	return c
}

// udp analyzes QUIC, IKEv2, and WireGuard associations.
func (a *Analyzer) udp(f *flow) []Connection {
	if len(f.order) == 0 {
		return nil
	}
	first := f.order[0]
	server := f.other(first)
	base := Connection{Client: first.String(), ClientIP: first.addr.String(), Server: server.String(), Count: 1, First: f.first, Last: f.last}
	dg := f.datagrams[first]
	if len(dg) == 0 {
		return nil
	}
	if h, ok := parseLongHeader(dg[0]); ok && h.typ == 0 {
		switch h.version {
		case quicV1:
			return []Connection{a.quicConn(base, f, first, server, h)}
		case quicV2:
			base.Protocol, base.Class, base.Outcome, base.KeyExchange = "QUIC v2", ClassUnknown, "incomplete", "—"
			base.Headline = "QUIC version 2 isn't decoded yet."
			return []Connection{base}
		}
	}
	if f.key.a.port == 500 || f.key.b.port == 500 || f.key.a.port == 4500 || f.key.b.port == 4500 {
		if c, ok := ikeConn(base, f); ok {
			return []Connection{c}
		}
	}
	for _, d := range dg {
		if wireguardType(d) == 1 {
			base.Protocol, base.Class, base.Outcome, base.KeyExchange = "WireGuard", ClassClassical, "wireguard", "X25519 (Noise IKpsk2)"
			base.Headline = "WireGuard handshakes use X25519: classical key exchange. A pre-shared key, if configured, adds a symmetric layer that the capture can't show."
			base.Limits = "Whether a pre-shared key is configured can't be seen on the wire."
			return []Connection{base}
		}
	}
	return nil
}

func (a *Analyzer) quicConn(c Connection, f *flow, client, server endpoint, h quicLong) Connection {
	c.Protocol = "QUIC"
	c.Limits = "Only QUIC Initial packets were decrypted (their keys are public); the rest of the connection wasn't."
	ck, err1 := quicInitialKeys(h.dcid, false)
	sk, err2 := quicInitialKeys(h.dcid, true)
	if err1 != nil || err2 != nil {
		c.Class, c.Outcome = ClassUnknown, "incomplete"
		return c
	}
	ccrypto, scrypto := map[uint64][]byte{}, map[uint64][]byte{}
	for _, d := range f.datagrams[client] {
		quicInitials(d, ck, ccrypto)
	}
	for _, d := range f.datagrams[server] {
		quicInitials(d, sk, scrypto)
	}
	var ch, sh *hello
	for _, m := range handshakeMessages(assembleCrypto(ccrypto)) {
		if m[0][0] == 1 && ch == nil {
			if h, ok := parseHello(m[1], true); ok {
				ch = &h
			}
		}
	}
	for _, m := range handshakeMessages(assembleCrypto(scrypto)) {
		if m[0][0] == 2 {
			if h, ok := parseHello(m[1], false); ok && !h.hrr {
				sh = &h
			}
		}
	}
	if ch == nil {
		c.Class, c.Outcome, c.KeyExchange = ClassUnknown, "incomplete", "—"
		c.Headline = "The QUIC ClientHello couldn't be read."
		return c
	}
	c.ServerName = ch.sni
	c.ClientOffersPQ = anyPQ(ch.groups) || anyPQ(ch.shares)
	c.Offered = groupList(ch.groups)
	c.fact("Client offered groups", groupList(ch.groups))
	c.fact("Client key shares", groupList(ch.shares))
	c.fact("Server name (SNI)", ch.sni)
	c.fact("ALPN", strings.Join(ch.alpn, ", "))
	if sh == nil {
		c.Class, c.Outcome, c.KeyExchange = ClassUnknown, "incomplete", "—"
		c.Headline = "The server's QUIC Initial isn't in the capture, so the negotiated group is unknown."
		return c
	}
	c.Version, c.Cipher = "TLS 1.3 (QUIC)", suiteName(sh.suites[0])
	c.KeyExchange = groupName(sh.selGroup)
	c.fact("Server chose", c.KeyExchange)
	switch {
	case pqGroup(sh.selGroup):
		c.Class, c.Outcome = ClassPQ, "pq"
		c.Headline = fmt.Sprintf("Negotiated %s over QUIC: post-quantum key exchange.", c.KeyExchange)
	case c.ClientOffersPQ:
		c.Class, c.Outcome = ClassClassical, "server-classical"
		c.Headline = fmt.Sprintf("The client offered ML-KEM, but the server chose %s over QUIC. Fix the server.", c.KeyExchange)
	default:
		c.Class, c.Outcome = ClassClassical, "client-classical"
		c.Headline = fmt.Sprintf("The client didn't offer ML-KEM, so the QUIC connection used %s. Fix the client.", c.KeyExchange)
	}
	return c
}

func ikeConn(c Connection, f *flow) (Connection, bool) {
	var req, resp *ikeMsg
	for _, s := range f.order {
		for _, d := range f.datagrams[s] {
			m, ok := parseIKE(d)
			if !ok {
				continue
			}
			if m.response && resp == nil && len(m.proposals) > 0 {
				resp = &m
			} else if !m.response && req == nil && len(m.proposals) > 0 {
				req = &m
			}
		}
	}
	if req == nil && resp == nil {
		return c, false
	}
	c.Protocol = "IKEv2"
	var offered []string
	if req != nil {
		for i, p := range req.proposals {
			var names []string
			for _, id := range keyExchanges(p) {
				names = append(names, ikeKEName(id))
				c.ClientOffersPQ = c.ClientOffersPQ || ikePQ(id)
			}
			offered = append(offered, strings.Join(names, " + "))
			c.fact(fmt.Sprintf("Initiator proposal %d", i+1), strings.Join(names, " + "))
		}
	}
	c.Offered = strings.Join(offered, "; ")
	if resp == nil {
		c.Class, c.Outcome, c.KeyExchange = ClassUnknown, "incomplete", "—"
		c.Headline = "The responder's IKE_SA_INIT isn't in the capture."
		return c, true
	}
	chosen := keyExchanges(resp.proposals[0])
	var names []string
	pq := false
	for _, id := range chosen {
		names = append(names, ikeKEName(id))
		pq = pq || ikePQ(id)
	}
	c.KeyExchange = strings.Join(names, " + ")
	c.fact("Responder chose", c.KeyExchange)
	switch {
	case pq:
		c.Class, c.Outcome = ClassPQ, "pq"
		c.Headline = fmt.Sprintf("IKE SA established with %s: post-quantum key exchange.", c.KeyExchange)
	case c.ClientOffersPQ:
		c.Class, c.Outcome = ClassClassical, "server-classical"
		c.Headline = fmt.Sprintf("The initiator offered ML-KEM, but the responder chose %s only. Fix the responder.", c.KeyExchange)
	default:
		c.Class, c.Outcome = ClassClassical, "classical"
		c.Headline = fmt.Sprintf("IKE SA established with %s only: classical key exchange. Neither side offered ML-KEM.", c.KeyExchange)
	}
	return c, true
}
