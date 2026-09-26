package observe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"pqscan/internal/probe"
)

// SSH: each side sends a banner line and then KEXINIT in the clear
// (RFC 4253 §4.2, §7.1). The method used is the first one in the client's list
// that the server also lists.

type sshSide struct {
	banner   string
	kex      []string
	hostKeys []string
}

func parseSSH(b []byte) (sshSide, bool) {
	var s sshSide
	i := bytes.Index(b[:min(len(b), 8192)], []byte("SSH-"))
	if i < 0 || i > 0 && b[i-1] != '\n' {
		return s, false
	}
	eol := bytes.IndexByte(b[i:], '\n')
	if eol < 0 {
		return s, false
	}
	s.banner = strings.TrimRight(string(b[i:i+eol]), "\r")
	b = b[i+eol+1:]
	if len(b) < 6 {
		return s, true
	}
	pktLen := int(binary.BigEndian.Uint32(b))
	if pktLen < 22 || 4+pktLen > len(b) {
		return s, true
	}
	pkt := b[4 : 4+pktLen]
	pad := int(pkt[0])
	if 1+pad > len(pkt) {
		return s, true
	}
	payload := pkt[1 : len(pkt)-pad]
	if len(payload) < 17 || payload[0] != 20 {
		return s, true
	}
	p := 17
	lists := make([][]string, 0, 2)
	for n := 0; n < 2; n++ {
		if p+4 > len(payload) {
			break
		}
		l := int(binary.BigEndian.Uint32(payload[p:]))
		if p+4+l > len(payload) {
			break
		}
		var names []string
		if l > 0 {
			names = strings.Split(string(payload[p+4:p+4+l]), ",")
		}
		lists = append(lists, names)
		p += 4 + l
	}
	if len(lists) > 0 {
		for _, k := range lists[0] {
			if !probe.IsSSHPseudoKex(k) {
				s.kex = append(s.kex, k)
			}
		}
	}
	if len(lists) > 1 {
		s.hostKeys = lists[1]
	}
	return s, true
}

func firstCommon(client, server []string) string {
	for _, c := range client {
		for _, s := range server {
			if c == s {
				return c
			}
		}
	}
	return ""
}

// IKEv2 IKE_SA_INIT (RFC 7296): the proposals and the key exchange are in the
// clear. RFC 9370 adds up to seven additional key exchanges (transform types
// 6-12); ML-KEM uses Key Exchange Method IDs 35-37 (draft-ietf-ipsecme-ikev2-mlkem).

var ikeKE = map[uint16]string{
	0: "NONE", 1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
	17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 22: "MODP-1024-160",
	23: "MODP-2048-224", 24: "MODP-2048-256", 25: "ECP-192", 26: "ECP-224", 27: "brainpoolP224r1",
	28: "brainpoolP256r1", 29: "brainpoolP384r1", 30: "brainpoolP512r1", 31: "Curve25519", 32: "Curve448",
	33: "GOST3410-2012-256", 34: "GOST3410-2012-512", 35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024",
}

func ikeKEName(id uint16) string {
	if n, ok := ikeKE[id]; ok {
		return n
	}
	return fmt.Sprintf("KE method %d", id)
}

func ikePQ(id uint16) bool { return id >= 35 && id <= 37 }

type ikeTransform struct {
	typ byte
	id  uint16
}

type ikeMsg struct {
	spiI      []byte
	response  bool
	proposals [][]ikeTransform
	ke        uint16
	hasKE     bool
}

// parseIKE reads an IKE_SA_INIT message. UDP 4500 prefixes a zero non-ESP marker.
func parseIKE(b []byte) (ikeMsg, bool) {
	if len(b) >= 4 && binary.BigEndian.Uint32(b) == 0 {
		b = b[4:]
	}
	var m ikeMsg
	if len(b) < 28 || b[17] != 0x20 || b[18] != 34 { // IKEv2, IKE_SA_INIT
		return m, false
	}
	if total := int(binary.BigEndian.Uint32(b[24:])); total < 28 || total > len(b) {
		return m, false
	} else {
		b = b[:total]
	}
	m.spiI = b[:8]
	m.response = b[19]&0x20 != 0
	next, p := b[16], 28
	for next != 0 && p+4 <= len(b) {
		typ := next
		next = b[p]
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		if l < 4 || p+l > len(b) {
			break
		}
		body := b[p+4 : p+l]
		switch typ {
		case 33: // SA
			for q := 0; q+8 <= len(body); {
				pl := int(binary.BigEndian.Uint16(body[q+2:]))
				if pl < 8 || q+pl > len(body) {
					break
				}
				prop := body[q : q+pl]
				spi, n := int(prop[6]), int(prop[7])
				var ts []ikeTransform
				for t, i := 8+spi, 0; i < n && t+8 <= len(prop); i++ {
					tl := int(binary.BigEndian.Uint16(prop[t+2:]))
					if tl < 8 || t+tl > len(prop) {
						break
					}
					ts = append(ts, ikeTransform{typ: prop[t+4], id: binary.BigEndian.Uint16(prop[t+6:])})
					t += tl
				}
				m.proposals = append(m.proposals, ts)
				q += pl
			}
		case 34: // KE
			if len(body) >= 2 {
				m.ke, m.hasKE = binary.BigEndian.Uint16(body), true
			}
		}
		p += l
	}
	return m, len(m.proposals) > 0 || m.hasKE
}

// keyExchanges lists a proposal's key exchange transforms: the primary (type 4)
// first, then the RFC 9370 additional ones (types 6-12), skipping NONE.
func keyExchanges(ts []ikeTransform) []uint16 {
	var out []uint16
	for _, typ := range []byte{4, 6, 7, 8, 9, 10, 11, 12} {
		for _, t := range ts {
			if t.typ == typ && t.id != 0 {
				out = append(out, t.id)
				break
			}
		}
	}
	return out
}

// WireGuard (Noise_IKpsk2 over X25519): handshake initiation is message type 1
// of 148 bytes, the response type 2 of 92 bytes.
func wireguardType(b []byte) byte {
	if len(b) >= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		switch {
		case b[0] == 1 && len(b) == 148, b[0] == 2 && len(b) == 92, b[0] == 3 && len(b) == 64:
			return b[0]
		}
	}
	return 0
}

// Plaintext application protocols, recognized from their first bytes.
func plaintextProtocol(client, server []byte, port uint16) string {
	c, s := string(client[:min(len(client), 16)]), string(server[:min(len(server), 16)])
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "} {
		if strings.HasPrefix(c, m) {
			return "HTTP"
		}
	}
	switch {
	case strings.HasPrefix(s, "HTTP/1."):
		return "HTTP"
	case strings.HasPrefix(s, "220") && (strings.HasPrefix(strings.ToUpper(c), "EHLO") || strings.HasPrefix(strings.ToUpper(c), "HELO")):
		return "SMTP"
	case strings.HasPrefix(s, "* OK"):
		return "IMAP"
	case strings.HasPrefix(s, "+OK"):
		return "POP3"
	case strings.HasPrefix(s, "220") && strings.HasPrefix(strings.ToUpper(c), "USER"):
		return "FTP"
	case len(client) >= 8 && binary.BigEndian.Uint32(client[4:]) == 0x00030000:
		return "PostgreSQL"
	case port == 23:
		return "Telnet"
	case port == 389 && len(client) > 0 && client[0] == 0x30:
		return "LDAP"
	}
	return ""
}
