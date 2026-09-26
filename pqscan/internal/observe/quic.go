package observe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// QUIC v1 Initial packets (RFC 9001 §5) are protected with keys derived from
// the client's Destination Connection ID, which travels in the clear, so
// anyone can read the ClientHello and ServerHello they carry.

var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

type quicKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func quicInitialKeys(dcid []byte, server bool) (quicKeys, error) {
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return quicKeys{}, err
	}
	label := "client in"
	if server {
		label = "server in"
	}
	secret := hkdfExpandLabel(sha256.New, initial, label, nil, 32)
	key := hkdfExpandLabel(sha256.New, secret, "quic key", nil, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return quicKeys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return quicKeys{}, err
	}
	hp, err := aes.NewCipher(hkdfExpandLabel(sha256.New, secret, "quic hp", nil, 16))
	if err != nil {
		return quicKeys{}, err
	}
	return quicKeys{aead: aead, iv: hkdfExpandLabel(sha256.New, secret, "quic iv", nil, 12), hp: hp}, nil
}

// varint reads a QUIC variable-length integer (RFC 9000 §16).
func varint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

// quicLong is the cleartext part of a long-header packet.
type quicLong struct {
	typ        byte // 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry (v1)
	version    uint32
	dcid, scid []byte
}

func parseLongHeader(b []byte) (quicLong, bool) {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return quicLong{}, false
	}
	h := quicLong{typ: (b[0] >> 4) & 3, version: binary.BigEndian.Uint32(b[1:])}
	p := 5
	dl := int(b[p])
	if dl > 20 || p+1+dl >= len(b) {
		return quicLong{}, false
	}
	h.dcid = b[p+1 : p+1+dl]
	p += 1 + dl
	sl := int(b[p])
	if sl > 20 || p+1+sl > len(b) {
		return quicLong{}, false
	}
	h.scid = b[p+1 : p+1+sl]
	return h, true
}

// quicInitials decrypts the Initial packets in one datagram (packets may be
// coalesced) and appends their CRYPTO frame data to crypto (offset → data).
// It returns the header of the first long-header packet.
func quicInitials(dgram []byte, keys quicKeys, crypto map[uint64][]byte) (quicLong, error) {
	var first quicLong
	for n := 0; len(dgram) > 0 && dgram[0]&0x80 != 0; n++ {
		h, ok := parseLongHeader(dgram)
		if !ok {
			return first, errors.New("malformed long header")
		}
		if n == 0 {
			first = h
		}
		if h.version != quicV1 || h.typ == 3 { // other versions and Retry: nothing to decrypt here
			return first, nil
		}
		p := 7 + len(h.dcid) + len(h.scid)
		if h.typ == 0 { // Initial: token
			tl, k, ok := varint(dgram[p:])
			if !ok || p+k+int(tl) > len(dgram) {
				return first, errors.New("bad token length")
			}
			p += k + int(tl)
		}
		length, k, ok := varint(dgram[p:])
		if !ok {
			return first, errors.New("bad length")
		}
		p += k
		end := p + int(length)
		if end > len(dgram) || length < 20 {
			return first, errors.New("truncated packet")
		}
		if h.typ != 0 { // Handshake and 0-RTT need secrets we don't have; skip them
			dgram = dgram[end:]
			continue
		}
		pkt := append([]byte(nil), dgram[:end]...)
		sample := pkt[p+4 : p+20]
		mask := make([]byte, 16)
		keys.hp.Encrypt(mask, sample)
		pkt[0] ^= mask[0] & 0x0f
		pnLen := int(pkt[0]&3) + 1
		var pn uint64
		for i := 0; i < pnLen; i++ {
			pkt[p+i] ^= mask[1+i]
			pn = pn<<8 | uint64(pkt[p+i])
		}
		nonce := append([]byte(nil), keys.iv...)
		for i := 0; i < 8; i++ {
			nonce[11-i] ^= byte(pn >> (8 * i))
		}
		payload, err := keys.aead.Open(nil, nonce, pkt[p+pnLen:], pkt[:p+pnLen])
		if err != nil {
			return first, errors.New("Initial packet failed to decrypt")
		}
		if err := quicFrames(payload, crypto); err != nil {
			return first, err
		}
		dgram = dgram[end:]
	}
	return first, nil
}

// quicFrames collects CRYPTO frames, skipping the other frames an Initial may carry.
func quicFrames(b []byte, crypto map[uint64][]byte) error {
	for len(b) > 0 {
		typ, k, ok := varint(b)
		if !ok {
			return errors.New("bad frame")
		}
		b = b[k:]
		switch {
		case typ == 0x00 || typ == 0x01: // PADDING, PING
		case typ == 0x02 || typ == 0x03: // ACK
			vals := 4
			for i := 0; i < vals; i++ {
				v, k, ok := varint(b)
				if !ok {
					return errors.New("bad ACK")
				}
				b = b[k:]
				if i == 2 {
					vals += 2 * int(v) // ACK ranges
				}
			}
			if typ == 0x03 {
				for i := 0; i < 3; i++ {
					_, k, ok := varint(b)
					if !ok {
						return errors.New("bad ACK")
					}
					b = b[k:]
				}
			}
		case typ == 0x06: // CRYPTO
			off, k1, ok1 := varint(b)
			if !ok1 {
				return errors.New("bad CRYPTO")
			}
			l, k2, ok2 := varint(b[k1:])
			if !ok2 || k1+k2+int(l) > len(b) {
				return errors.New("bad CRYPTO")
			}
			crypto[off] = append([]byte(nil), b[k1+k2:k1+k2+int(l)]...)
			b = b[k1+k2+int(l):]
		case typ == 0x1c || typ == 0x1d: // CONNECTION_CLOSE
			return nil
		default:
			return nil // frames Initial packets don't carry
		}
	}
	return nil
}

// assembleCrypto joins CRYPTO data contiguously from offset 0.
func assembleCrypto(crypto map[uint64][]byte) []byte {
	var out []byte
	for progress := true; progress; {
		progress = false
		for off, d := range crypto {
			end := off + uint64(len(d))
			if off <= uint64(len(out)) && end > uint64(len(out)) {
				out = append(out, d[uint64(len(out))-off:]...)
				progress = true
			}
		}
	}
	return out
}
