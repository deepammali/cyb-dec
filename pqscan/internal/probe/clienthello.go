package probe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// helloRetryRandom is the fixed SHA-256 value a TLS 1.3 server puts in the
// ServerHello.random to signal a HelloRetryRequest (RFC 8446 §4.1.3).
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func u16(n uint16) []byte { return []byte{byte(n >> 8), byte(n)} }

// ext assembles a TLS extension: type(2) || length(2) || data.
func ext(typ uint16, data []byte) []byte {
	b := u16(typ)
	b = append(b, u16(uint16(len(data)))...)
	return append(b, data...)
}

// buildClientHello returns a complete TLS 1.3 record (handshake/ClientHello)
// offering the given groups (in order), each with a valid key_share. We pair the
// group under test with a classical fallback (X25519): real clients always offer
// the hybrid alongside a classical group, and servers reject a PQC-only hello with
// handshake_failure. The server then selects one — reading its pick tells us
// whether it took the post-quantum group or fell back to classical.
func buildClientHello(serverName string, groups ...uint16) ([]byte, error) {
	// server_name (SNI)
	name := []byte(serverName)
	sniList := append([]byte{0x00}, u16(uint16(len(name)))...) // name_type=host_name(0)
	sniList = append(sniList, name...)
	sni := ext(0x0000, append(u16(uint16(len(sniList))), sniList...))

	// supported_versions -> TLS 1.3 only
	sv := ext(0x002b, []byte{0x02, 0x03, 0x04})

	// supported_groups -> the listed groups
	var sgl bytes.Buffer
	for _, g := range groups {
		sgl.Write(u16(g))
	}
	sg := ext(0x000a, append(u16(uint16(sgl.Len())), sgl.Bytes()...))

	// signature_algorithms -> a standard set so the hello is well-formed
	schemes := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0203}
	var sab bytes.Buffer
	sab.Write(u16(uint16(len(schemes) * 2)))
	for _, s := range schemes {
		sab.Write(u16(s))
	}
	sa := ext(0x000d, sab.Bytes())

	// key_share -> one entry per group: group || len || key_exchange
	var kse bytes.Buffer
	for _, g := range groups {
		share, err := buildKeyShare(g)
		if err != nil {
			return nil, err
		}
		kse.Write(u16(g))
		kse.Write(u16(uint16(len(share))))
		kse.Write(share)
	}
	ks := ext(0x0033, append(u16(uint16(kse.Len())), kse.Bytes()...))

	exts := bytes.Join([][]byte{sni, sv, sg, sa, ks}, nil)

	var body bytes.Buffer
	body.Write(u16(0x0303)) // legacy_version
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	body.Write(random)
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		return nil, err
	}
	body.WriteByte(32) // legacy_session_id length
	body.Write(sid)
	// AES-256 first: a server that still picks AES-128 is showing its own preference.
	body.Write(u16(6)) // cipher_suites length
	body.Write(u16(0x1302))
	body.Write(u16(0x1301))
	body.Write(u16(0x1303))
	body.Write([]byte{0x01, 0x00}) // compression_methods
	body.Write(u16(uint16(len(exts))))
	body.Write(exts)

	// handshake header: msg_type(1)=client_hello || length(3)
	hs := make([]byte, 0, body.Len()+4)
	hs = append(hs, 0x01)
	bl := body.Len()
	hs = append(hs, byte(bl>>16), byte(bl>>8), byte(bl))
	hs = append(hs, body.Bytes()...)

	// record header: handshake(22) || legacy_version 0x0301 || length
	rec := make([]byte, 0, len(hs)+5)
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = append(rec, u16(uint16(len(hs)))...)
	rec = append(rec, hs...)
	return rec, nil
}

// serverChoice is the outcome of parsing a server's response to our ClientHello.
type serverChoice struct {
	Selected uint16 // the group the server picked; 0 = no key_share (TLS 1.2 or earlier)
	Cipher   uint16 // the cipher suite the server picked
	Found    bool   // a ServerHello was parsed
	HRR      bool   // server sent a HelloRetryRequest
	Alert    bool   // server refused the offer with an alert
}

// parseServerResponse reads TLS records from buf and extracts the server's
// selected group from the first ServerHello (or HelloRetryRequest), or reports an
// alert. The selected group lives in the (unencrypted) key_share extension.
func parseServerResponse(buf []byte) (serverChoice, error) {
	off := 0
	for off+5 <= len(buf) {
		ct := buf[off]
		recLen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
		if off+5+recLen > len(buf) {
			break
		}
		rec := buf[off+5 : off+5+recLen]
		switch ct {
		case 0x15: // alert
			return serverChoice{Alert: true}, nil
		case 0x16: // handshake
			if len(rec) >= 1 && rec[0] == 0x02 { // ServerHello
				if c, err := parseServerHello(rec); err == nil {
					return c, nil
				}
			}
		}
		off += 5 + recLen
	}
	return serverChoice{}, errors.New("no ServerHello or alert in response")
}

func parseServerHello(rec []byte) (serverChoice, error) {
	// rec: msg_type(1) || length(3) || body
	if len(rec) < 4 {
		return serverChoice{}, errors.New("short handshake")
	}
	p := 4
	if p+2+32 > len(rec) {
		return serverChoice{}, errors.New("short ServerHello")
	}
	p += 2 // legacy_version
	hrr := bytes.Equal(rec[p:p+32], helloRetryRandom)
	p += 32 // random
	if p >= len(rec) {
		return serverChoice{}, errors.New("truncated at session_id")
	}
	sidLen := int(rec[p])
	p += 1 + sidLen
	if p+3 > len(rec) {
		return serverChoice{}, errors.New("truncated at cipher_suite")
	}
	choice := serverChoice{Found: true, HRR: hrr, Cipher: binary.BigEndian.Uint16(rec[p : p+2])}
	p += 2 // cipher_suite
	p += 1 // compression_method
	if p+2 > len(rec) {
		return choice, nil // no extensions: a pre-TLS 1.3 ServerHello
	}
	extLen := int(binary.BigEndian.Uint16(rec[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(rec) {
		end = len(rec)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(rec[p : p+2])
		elen := int(binary.BigEndian.Uint16(rec[p+2 : p+4]))
		if p+4+elen > len(rec) {
			break
		}
		edata := rec[p+4 : p+4+elen]
		if etype == 0x0033 && len(edata) >= 2 { // key_share
			choice.Selected = binary.BigEndian.Uint16(edata[:2])
			return choice, nil
		}
		p += 4 + elen
	}
	return choice, nil // no key_share: the server negotiated TLS 1.2 or earlier
}
