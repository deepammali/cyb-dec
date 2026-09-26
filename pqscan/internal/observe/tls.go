package observe

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strings"

	"pqscan/internal/probe"
)

// TLS named groups beyond the ones the prober offers.
var extraGroups = map[uint16]string{
	0x0019: "secp521r1", 0x001E: "X448",
	0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
	0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024", // draft-ietf-tls-mlkem (pure ML-KEM)
}

func groupName(id uint16) string {
	if n, ok := extraGroups[id]; ok {
		return n
	}
	return probe.GroupName(id)
}

// pqGroup reports whether a TLS named group includes ML-KEM (or the legacy Kyber draft).
func pqGroup(id uint16) bool {
	switch id {
	case probe.GroupX25519MLKEM768, probe.GroupSecP256r1MLKEM768, probe.GroupSecP384r1MLKEM1024, probe.GroupX25519Kyber768D00,
		0x0200, 0x0201, 0x0202:
		return true
	}
	return false
}

func grease(id uint16) bool { return id&0x0f0f == 0x0a0a && id>>8 == id&0xff }

// Signature schemes seen in CertificateVerify (RFC 8446 §4.2.3; ML-DSA from draft-ietf-tls-mldsa).
var sigSchemes = map[uint16]string{
	0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
	0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}

type record struct {
	typ  byte
	data []byte // the record body
	hdr  []byte // the 5-byte header (AEAD additional data in TLS 1.3)
}

// records splits a TLS byte stream into records; it stops at a malformed header.
func records(b []byte) []record {
	var out []record
	for len(b) >= 5 {
		typ := b[0]
		if typ < 20 || typ > 24 || b[1] != 3 {
			break
		}
		l := int(binary.BigEndian.Uint16(b[3:]))
		if 5+l > len(b) {
			out = append(out, record{typ: typ, hdr: b[:5], data: b[5:]})
			break
		}
		out = append(out, record{typ: typ, hdr: b[:5], data: b[5 : 5+l]})
		b = b[5+l:]
	}
	return out
}

// findHello returns the offset of the first TLS handshake record carrying
// message type msg (1 ClientHello, 2 ServerHello) in the first 64 KiB, or -1.
// A nonzero offset means a plaintext preamble came first (STARTTLS, SSLRequest).
func findHello(b []byte, msg byte) int {
	lim := min(len(b), 64<<10)
	for i := 0; i+6 <= lim; i++ {
		if b[i] == 0x16 && b[i+1] == 3 && b[i+2] <= 4 && b[i+5] == msg {
			if l := int(binary.BigEndian.Uint16(b[i+3:])); l > 4 && l <= 1<<14+2048 {
				return i
			}
		}
	}
	return -1
}

type hello struct {
	random     []byte
	legacyVer  uint16
	suites     []uint16 // client offer, or the one the server chose
	groups     []uint16 // client supported_groups
	shares     []uint16 // client key shares
	versions   []uint16
	sni        string
	alpn       []string
	selVersion uint16 // server: supported_versions selection
	selGroup   uint16 // server: key_share group
	hrr        bool
}

var hrrRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// handshakeMessages splits handshake bytes into (type, body) messages.
func handshakeMessages(b []byte) [][2][]byte {
	var out [][2][]byte
	for len(b) >= 4 {
		l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if 4+l > len(b) {
			break
		}
		out = append(out, [2][]byte{b[:1], b[4 : 4+l]})
		b = b[4+l:]
	}
	return out
}

func parseHello(body []byte, client bool) (hello, bool) {
	var h hello
	if len(body) < 38 {
		return h, false
	}
	h.legacyVer = binary.BigEndian.Uint16(body)
	h.random = body[2:34]
	p := 34
	sid := int(body[p])
	p += 1 + sid
	if client {
		if p+2 > len(body) {
			return h, false
		}
		n := int(binary.BigEndian.Uint16(body[p:]))
		p += 2
		if p+n > len(body) {
			return h, false
		}
		for i := 0; i+1 < n; i += 2 {
			if s := binary.BigEndian.Uint16(body[p+i:]); !grease(s) {
				h.suites = append(h.suites, s)
			}
		}
		p += n
		if p >= len(body) {
			return h, false
		}
		p += 1 + int(body[p]) // compression methods
	} else {
		if p+3 > len(body) {
			return h, false
		}
		h.suites = []uint16{binary.BigEndian.Uint16(body[p:])}
		p += 3 // suite + compression
		h.hrr = bytes.Equal(h.random, hrrRandom)
	}
	if p+2 > len(body) {
		return h, true // no extensions
	}
	end := p + 2 + int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if end > len(body) {
		end = len(body)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(body[p:])
		l := int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+l > end {
			break
		}
		e := body[p : p+l]
		p += l
		switch typ {
		case 0: // server_name
			if client && len(e) >= 5 && e[2] == 0 {
				n := int(binary.BigEndian.Uint16(e[3:]))
				if 5+n <= len(e) {
					h.sni = string(e[5 : 5+n])
				}
			}
		case 10: // supported_groups
			if client && len(e) >= 2 {
				for i := 2; i+1 < len(e); i += 2 {
					if g := binary.BigEndian.Uint16(e[i:]); !grease(g) {
						h.groups = append(h.groups, g)
					}
				}
			}
		case 16: // ALPN
			if client && len(e) >= 2 {
				for i := 2; i < len(e); {
					n := int(e[i])
					if i+1+n > len(e) {
						break
					}
					h.alpn = append(h.alpn, string(e[i+1:i+1+n]))
					i += 1 + n
				}
			}
		case 43: // supported_versions
			if client && len(e) >= 1 {
				for i := 1; i+1 < len(e); i += 2 {
					if v := binary.BigEndian.Uint16(e[i:]); !grease(v) {
						h.versions = append(h.versions, v)
					}
				}
			} else if !client && len(e) == 2 {
				h.selVersion = binary.BigEndian.Uint16(e)
			}
		case 51: // key_share
			if client && len(e) >= 2 {
				for i := 2; i+4 <= len(e); {
					g := binary.BigEndian.Uint16(e[i:])
					n := int(binary.BigEndian.Uint16(e[i+2:]))
					if !grease(g) {
						h.shares = append(h.shares, g)
					}
					i += 4 + n
				}
			} else if !client && len(e) >= 2 {
				h.selGroup = binary.BigEndian.Uint16(e) // ServerHello share, or the HRR's selected_group
			}
		}
	}
	return h, true
}

// tlsSide is what one direction of a TLS connection shows in plaintext.
type tlsSide struct {
	hellos   []hello
	certs    [][]byte // TLS 1.2 Certificate (plaintext)
	ske      []byte   // TLS 1.2 ServerKeyExchange
	encStart int      // index in recs of the first encrypted record
	recs     []record
}

// plaintextSide parses the unencrypted handshake of one direction.
func plaintextSide(b []byte, client bool) tlsSide {
	var side tlsSide
	side.recs = records(b)
	side.encStart = len(side.recs)
	var hs []byte
	for i, r := range side.recs {
		if r.typ == 23 {
			side.encStart = i
			break
		}
		if r.typ == 22 {
			hs = append(hs, r.data...)
		}
	}
	msg := byte(2)
	if client {
		msg = 1
	}
	for _, m := range handshakeMessages(hs) {
		switch m[0][0] {
		case msg:
			if h, ok := parseHello(m[1], client); ok {
				side.hellos = append(side.hellos, h)
			}
		case 11: // TLS 1.2 Certificate
			side.certs = certList(m[1], false)
		case 12: // TLS 1.2 ServerKeyExchange
			side.ske = m[1]
		}
	}
	return side
}

// certList reads a Certificate message: TLS 1.3 adds a request context and per-entry extensions.
func certList(b []byte, tls13 bool) [][]byte {
	if tls13 {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return nil
		}
		b = b[1+int(b[0]):]
	}
	if len(b) < 3 {
		return nil
	}
	b = b[3:]
	var out [][]byte
	for len(b) >= 3 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if 3+n > len(b) {
			break
		}
		out = append(out, b[3:3+n])
		b = b[3+n:]
		if tls13 {
			if len(b) < 2 || len(b) < 2+int(binary.BigEndian.Uint16(b)) {
				break
			}
			b = b[2+int(binary.BigEndian.Uint16(b)):]
		}
	}
	return out
}

func suiteName(id uint16) string { return tls.CipherSuiteName(id) }

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04X", v)
}

func groupList(ids []uint16) string {
	var names []string
	for _, id := range ids {
		names = append(names, groupName(id))
	}
	return strings.Join(names, ", ")
}

// tls12KeyExchange names the key exchange of a TLS 1.2 suite and its ServerKeyExchange.
func tls12KeyExchange(suite uint16, ske []byte) (string, bool) {
	name := suiteName(suite)
	switch {
	case strings.HasPrefix(name, "TLS_RSA_"):
		return "RSA key transport (static RSA)", true
	case strings.Contains(name, "ECDHE") && len(ske) >= 3 && ske[0] == 3:
		return groupName(binary.BigEndian.Uint16(ske[1:])) + " (ECDHE)", false
	case strings.Contains(name, "ECDHE"):
		return "ECDHE", false
	case strings.Contains(name, "DHE"):
		return "finite-field DHE", false
	}
	return "unknown key exchange", false
}
