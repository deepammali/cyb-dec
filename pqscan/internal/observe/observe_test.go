package observe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "svc.corp.local"}, DNSNames: []string{"svc.corp.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func only(t *testing.T, r Report) Connection {
	t.Helper()
	if len(r.Groups) != 1 {
		t.Fatalf("want 1 connection group, got %d: %+v", len(r.Groups), r.Groups)
	}
	return r.Groups[0]
}

func TestTLSOutcomes(t *testing.T) {
	cert := serverCert(t)
	cases := []struct {
		name                       string
		serverCurves, clientCurves []tls.CurveID
		serverMax                  uint16
		class                      Class
		outcome, kex               string
		offersPQ                   bool
	}{
		{"both post-quantum", nil, nil, 0, ClassPQ, "pq", "X25519MLKEM768", true},
		{"server refuses ML-KEM", []tls.CurveID{tls.X25519}, nil, 0, ClassClassical, "server-classical", "X25519", true},
		{"client never offers ML-KEM", nil, []tls.CurveID{tls.X25519, tls.CurveP256}, 0, ClassClassical, "client-classical", "X25519", false},
		{"tls 1.2", nil, nil, tls.VersionTLS12, ClassClassical, "tls12", "X25519 (ECDHE)", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: tc.serverCurves, MaxVersion: tc.serverMax}
			cc := &tls.Config{ServerName: "svc.corp.local", InsecureSkipVerify: true, CurvePreferences: tc.clientCurves}
			chunks, _ := tlsExchange(t, sc, cc, []byte("ping"), []byte("pong"))
			c := newCapture()
			c.tcpSession(cli, srv, chunks)
			r := c.analyze(t, Options{})
			g := only(t, r)
			if g.Protocol != "TLS" || g.Class != tc.class || g.Outcome != tc.outcome || g.KeyExchange != tc.kex || g.ClientOffersPQ != tc.offersPQ || g.ServerName != "svc.corp.local" {
				t.Fatalf("got %s/%s/%s kex %q offersPQ %v sni %q: %s", g.Protocol, g.Class, g.Outcome, g.KeyExchange, g.ClientOffersPQ, g.ServerName, g.Headline)
			}
			if tc.outcome == "client-classical" && (len(r.Clients) != 1 || r.Clients[0] != "10.0.0.5") {
				t.Errorf("clients without ML-KEM: %v", r.Clients)
			}
			if tc.outcome == "tls12" && !hasFact(g, "Server certificate", "EC P-256") {
				t.Errorf("TLS 1.2 certificate evidence missing: %+v", g.Evidence)
			}
		})
	}
}

func hasFact(c Connection, label, contains string) bool {
	for _, f := range c.Evidence {
		if f.Label == label && strings.Contains(f.Value, contains) {
			return true
		}
	}
	return false
}

// A key log opens TLS 1.3 sessions; what they carry goes through the at-rest detectors.
func TestKeyLogDecryption(t *testing.T) {
	var klog bytes.Buffer
	jwe := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM"}`)) + ".a.b.c.d"
	request := []byte("GET /v1/pay HTTP/1.1\r\nHost: svc\r\nAuthorization: Bearer " + jwe + "\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\n\r\nage-encryption.org/v1\n-> X25519 dGVzdA\nYm9keQ\n--- bWFj\n")
	sc := &tls.Config{Certificates: []tls.Certificate{serverCert(t)}}
	cc := &tls.Config{ServerName: "svc.corp.local", InsecureSkipVerify: true, KeyLogWriter: &klog}
	chunks, state := tlsExchange(t, sc, cc, request, response)
	c := newCapture()
	c.tcpSession(cli, srv, chunks)

	kl, err := ParseKeyLog(bytes.NewReader(klog.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	r := c.analyze(t, Options{KeyLog: kl})
	g := only(t, r)
	if state.CipherSuite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		if !strings.Contains(g.Decryption, "golang.org/x/crypto") {
			t.Fatalf("ChaCha20 session: decryption %q", g.Decryption)
		}
		t.Skip("this machine negotiated ChaCha20-Poly1305, which this build can't decrypt")
	}
	if g.Decryption != "decrypted" || r.KeyLog.Decrypted != 1 {
		t.Fatalf("decryption %q, keylog %+v", g.Decryption, r.KeyLog)
	}
	if !hasFact(g, "Server certificate", "EC P-256") || !hasFact(g, "Server signature", "ecdsa_secp256r1_sha256") {
		t.Errorf("decrypted handshake evidence: %+v", g.Evidence)
	}
	formats := map[string]string{}
	for _, f := range r.Findings {
		formats[f.Format] = string(f.Class)
	}
	if formats["JWE token (encrypted)"] != "exposed" || formats["age encrypted file"] != "exposed" {
		t.Errorf("payload findings: %v", formats)
	}
	ids := map[string]bool{}
	for _, rec := range r.Recommendations {
		ids[rec.ID] = true
	}
	if !ids["reencrypt-pq"] {
		t.Errorf("payload recommendations missing: %v", ids)
	}

	// Without this session's secrets, the connection is reported as not decrypted.
	other, _ := ParseKeyLog(strings.NewReader("CLIENT_TRAFFIC_SECRET_0 " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32) + "\n"))
	g = only(t, c.analyze(t, Options{KeyLog: other}))
	if !strings.Contains(g.Decryption, "no entry") {
		t.Errorf("unmatched key log: %q", g.Decryption)
	}
}

func TestQUICInitialsRFC9001(t *testing.T) {
	f, err := os.Open("testdata/rfc9001-initials.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkts := map[string][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8192), 8192)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && !strings.HasPrefix(fields[0], "#") {
			pkts[fields[0]], _ = hex.DecodeString(fields[1])
		}
	}
	// The key schedule matches RFC 9001 A.1.
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	k, _ := quicInitialKeys(dcid, false)
	if hex.EncodeToString(k.iv) != "fa044b2f42a3fd3b46fb255c" {
		t.Fatalf("client iv %x", k.iv)
	}
	client, server := netip.MustParseAddrPort("10.0.0.5:61000"), netip.MustParseAddrPort("93.184.216.34:443")
	c := newCapture()
	c.udp(client, server, pkts["client"])
	c.udp(server, client, pkts["server"])
	g := only(t, c.analyze(t, Options{}))
	if g.Protocol != "QUIC" || g.ServerName != "example.com" || g.KeyExchange != "X25519" || g.Outcome != "client-classical" ||
		g.Offered != "X25519, secp256r1, secp384r1" || g.Cipher != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("QUIC: %+v", g)
	}
}

func sshKexinit(kex ...string) []byte {
	lists := [][]byte{[]byte(strings.Join(kex, ",")), []byte("ssh-ed25519,rsa-sha2-512")}
	for i := 0; i < 8; i++ {
		lists = append(lists, []byte("aes128-ctr"))
	}
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, l := range lists {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(l)))
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, pad)...)
}

func TestSSH(t *testing.T) {
	cases := []struct {
		name           string
		client, server []string
		outcome, kex   string
	}{
		{"post-quantum", []string{"mlkem768x25519-sha256", "curve25519-sha256", "ext-info-c"}, []string{"mlkem768x25519-sha256", "curve25519-sha256"}, "pq", "mlkem768x25519-sha256"},
		{"old server", []string{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256"}, []string{"curve25519-sha256", "ecdh-sha2-nistp256"}, "server-classical", "curve25519-sha256"},
		{"client order", []string{"curve25519-sha256", "mlkem768x25519-sha256"}, []string{"mlkem768x25519-sha256", "curve25519-sha256"}, "client-classical", "curve25519-sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapture()
			s := netip.MustParseAddrPort("10.0.0.9:22")
			c.tcpSession(cli, s, []chunk{
				{false, []byte("SSH-2.0-OpenSSH_9.9\r\n")},
				{true, []byte("SSH-2.0-OpenSSH_9.6\r\n")},
				{true, sshKexinit(tc.client...)},
				{false, sshKexinit(tc.server...)},
			})
			g := only(t, c.analyze(t, Options{}))
			if g.Protocol != "SSH" || g.Outcome != tc.outcome || g.KeyExchange != tc.kex {
				t.Fatalf("SSH: %s %s: %s", g.Outcome, g.KeyExchange, g.Headline)
			}
		})
	}
}

// PGP message with an RSA recipient (RFC 9580 PKESK v3 + SEIPD v1), armored.
func armoredPGP() string {
	pkesk := append([]byte{0xC1, 13, 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 8, 0x80}, []byte{}...)
	pkesk[1] = byte(len(pkesk) - 2)
	seipd := append([]byte{0xD2, 21, 1}, make([]byte, 20)...)
	return "-----BEGIN PGP MESSAGE-----\n\n" + base64.StdEncoding.EncodeToString(append(pkesk, seipd...)) + "\n-----END PGP MESSAGE-----\n"
}

func TestPlaintextAndStartTLS(t *testing.T) {
	smtp := netip.MustParseAddrPort("10.0.0.9:25")
	c := newCapture()
	c.tcpSession(cli, smtp, []chunk{
		{false, []byte("220 mx.corp.local ESMTP\r\n")},
		{true, []byte("EHLO a\r\nMAIL FROM:<a@corp.local>\r\nRCPT TO:<b@corp.local>\r\nDATA\r\n")},
		{false, []byte("250 ok\r\n354 go ahead\r\n")},
		{true, []byte("Subject: secret\r\n\r\n" + armoredPGP() + "\r\n.\r\n")},
	})
	r := c.analyze(t, Options{})
	g := only(t, r)
	if g.Protocol != "SMTP" || g.Class != ClassPlaintext || len(g.Findings) != 1 || g.Findings[0].Class != "exposed" {
		t.Fatalf("plaintext SMTP: %+v", g)
	}

	// STARTTLS: the TLS handshake follows a plaintext preamble.
	sc := &tls.Config{Certificates: []tls.Certificate{serverCert(t)}}
	cc := &tls.Config{ServerName: "svc.corp.local", InsecureSkipVerify: true}
	chunks, _ := tlsExchange(t, sc, cc, []byte("x"), []byte("y"))
	pre := []chunk{{false, []byte("220 mx ESMTP\r\n")}, {true, []byte("EHLO a\r\n")}, {false, []byte("250-mx\r\n250 STARTTLS\r\n")}, {true, []byte("STARTTLS\r\n")}, {false, []byte("220 go ahead\r\n")}}
	c = newCapture()
	c.tcpSession(cli, smtp, append(pre, chunks...))
	g = only(t, c.analyze(t, Options{}))
	if g.Protocol != "SMTP STARTTLS" || g.Class != ClassPQ {
		t.Fatalf("STARTTLS: %s %s: %s", g.Protocol, g.Class, g.Headline)
	}
}

func ikeSAInit(response bool, transforms ...[2]uint16) []byte {
	var ts []byte
	for i, t := range transforms {
		last := byte(3)
		if i == len(transforms)-1 {
			last = 0
		}
		ts = append(ts, last, 0, 0, 8, byte(t[0]), 0, byte(t[1]>>8), byte(t[1]))
	}
	prop := append([]byte{0, 0, 0, 0, 1, 1, 0, byte(len(transforms))}, ts...)
	binary.BigEndian.PutUint16(prop[2:], uint16(len(prop)))
	sa := append([]byte{34, 0, 0, 0}, prop...) // next payload: KE
	binary.BigEndian.PutUint16(sa[2:], uint16(len(sa)))
	ke := append([]byte{0, 0, 0, 0, 0, byte(transforms[2][1]), 0, 0}, make([]byte, 32)...)
	binary.BigEndian.PutUint16(ke[2:], uint16(len(ke)))
	hdr := make([]byte, 28)
	copy(hdr, "SPI-INIT")
	hdr[16], hdr[17], hdr[18] = 33, 0x20, 34
	if response {
		hdr[19] = 0x20
		copy(hdr[8:], "SPI-RESP")
	} else {
		hdr[19] = 0x08
	}
	msg := append(append(hdr, sa...), ke...)
	binary.BigEndian.PutUint32(msg[24:], uint32(len(msg)))
	return msg
}

func TestIKEv2AndWireGuard(t *testing.T) {
	peer, gw := netip.MustParseAddrPort("10.0.0.5:500"), netip.MustParseAddrPort("10.0.0.1:500")
	hybrid := [][2]uint16{{1, 20}, {2, 5}, {4, 31}, {6, 36}}
	c := newCapture()
	c.udp(peer, gw, ikeSAInit(false, hybrid...))
	c.udp(gw, peer, ikeSAInit(true, hybrid...))
	g := only(t, c.analyze(t, Options{}))
	if g.Protocol != "IKEv2" || g.Class != ClassPQ || g.KeyExchange != "Curve25519 + ML-KEM-768" {
		t.Fatalf("IKEv2 hybrid: %+v", g)
	}

	c = newCapture()
	c.udp(peer, gw, ikeSAInit(false, hybrid...))
	c.udp(gw, peer, ikeSAInit(true, [2]uint16{1, 20}, [2]uint16{2, 5}, [2]uint16{4, 19}))
	g = only(t, c.analyze(t, Options{}))
	if g.Outcome != "server-classical" || g.KeyExchange != "ECP-256" {
		t.Fatalf("IKEv2 responder without ML-KEM: %+v", g)
	}

	c = newCapture()
	wg := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	c.udp(netip.MustParseAddrPort("10.0.0.5:40000"), netip.MustParseAddrPort("10.0.0.1:51820"), wg)
	g = only(t, c.analyze(t, Options{}))
	if g.Protocol != "WireGuard" || g.Class != ClassClassical {
		t.Fatalf("WireGuard: %+v", g)
	}
}

func TestReassemblyAndPcapng(t *testing.T) {
	s := &stream{limit: 1 << 20}
	s.add(100, true, nil)
	s.add(111, false, []byte("world"))  // out of order
	s.add(101, false, []byte("hello ")) // fills to 107
	s.add(101, false, []byte("hello ")) // retransmission
	s.add(107, false, []byte("big "))   // fills to 111, which releases "world"
	if string(s.data) != "hello big world" {
		t.Fatalf("reassembled %q", s.data)
	}

	// The same TLS session read from pcapng gives the same result.
	sc := &tls.Config{Certificates: []tls.Certificate{serverCert(t)}}
	cc := &tls.Config{ServerName: "svc.corp.local", InsecureSkipVerify: true}
	chunks, _ := tlsExchange(t, sc, cc, []byte("x"), []byte("y"))
	c := newCapture()
	c.tcpSession(cli, srv, chunks)
	ng := toPcapng(t, c.buf.Bytes())
	a := New(context.Background(), Options{})
	if err := a.Add(bytes.NewReader(ng)); err != nil {
		t.Fatal(err)
	}
	g := only(t, a.Report())
	if g.Class != ClassPQ || g.First.Year() != 2026 {
		t.Fatalf("pcapng: %+v", g)
	}

	if err := New(context.Background(), Options{}).Add(strings.NewReader("not a capture")); err == nil {
		t.Fatal("garbage accepted as a capture")
	}
}

// toPcapng rewrites a classic pcap as pcapng (SHB, one IDB, EPBs).
func toPcapng(t *testing.T, pcap []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		l := uint32(12 + len(body))
		binary.Write(&out, binary.LittleEndian, typ)
		binary.Write(&out, binary.LittleEndian, l)
		out.Write(body)
		binary.Write(&out, binary.LittleEndian, l)
	}
	shb := binary.LittleEndian.AppendUint32(nil, 0x1a2b3c4d)
	shb = append(shb, 1, 0, 0, 0)
	shb = binary.LittleEndian.AppendUint64(shb, ^uint64(0))
	block(0x0a0d0d0a, shb)
	idb := []byte{1, 0, 0, 0}
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	block(1, idb)
	p := 24
	for p+16 <= len(pcap) {
		sec, usec := binary.LittleEndian.Uint32(pcap[p:]), binary.LittleEndian.Uint32(pcap[p+4:])
		n := int(binary.LittleEndian.Uint32(pcap[p+8:]))
		ts := uint64(sec)*1e6 + uint64(usec)
		epb := binary.LittleEndian.AppendUint32(nil, 0)
		epb = binary.LittleEndian.AppendUint32(epb, uint32(ts>>32))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(ts))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(n))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(n))
		epb = append(epb, pcap[p+16:p+16+n]...)
		block(6, epb)
		p += 16 + n
	}
	return out.Bytes()
}
