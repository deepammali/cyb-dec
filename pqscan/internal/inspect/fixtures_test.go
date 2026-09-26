package inspect

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// Builders for hermetic fixtures, laid out byte for byte from the specs.

// DER

func tlv(class, tag int, constructed bool, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	b := byte(class<<6 | tag)
	if constructed {
		b |= 0x20
	}
	out := []byte{b}
	switch l := len(body); {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 0x100:
		out = append(out, 0x81, byte(l))
	case l < 0x10000:
		out = append(out, 0x82, byte(l>>8), byte(l))
	default:
		out = append(out, 0x83, byte(l>>16), byte(l>>8), byte(l))
	}
	return append(out, body...)
}

func seq(parts ...[]byte) []byte          { return tlv(0, 16, true, parts...) }
func set(parts ...[]byte) []byte          { return tlv(0, 17, true, parts...) }
func octets(b []byte) []byte              { return tlv(0, 4, false, b) }
func bitString(b []byte) []byte           { return tlv(0, 3, false, append([]byte{0}, b...)) }
func ctx(tag int, parts ...[]byte) []byte { return tlv(2, tag, true, parts...) }
func integer(n int) []byte                { b, _ := asn1.Marshal(n); return b }
func nullDER() []byte                     { return []byte{5, 0} }

func oid(s string) []byte {
	var id asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		id = append(id, n)
	}
	b, err := asn1.Marshal(id)
	if err != nil {
		panic(err)
	}
	return b
}

func algID(o string, params ...[]byte) []byte { return seq(append([][]byte{oid(o)}, params...)...) }

func contentInfo(o string, content []byte) []byte { return seq(oid(o), ctx(0, content)) }

// issuerAndSerial is a minimal rid.
func issuerAndSerial() []byte { return seq(seq(), integer(7)) }

func ktri(keyAlg string) []byte {
	return seq(integer(0), issuerAndSerial(), algID(keyAlg, nullDER()), octets(make([]byte, 16)))
}

func kari() []byte {
	return ctx(1, integer(3), ctx(0, seq()), algID("1.3.132.1.11.1", algID("2.16.840.1.101.3.4.1.45")), seq())
}

func kemri(kem string) []byte {
	k := seq(integer(0), issuerAndSerial(), algID(kem), octets(make([]byte, 32)), algID("1.2.840.113549.1.9.16.3.28"),
		integer(32), algID("2.16.840.1.101.3.4.1.45"), octets(make([]byte, 40)))
	return ctx(4, oid(oidORIKEM), k)
}

func pwri() []byte {
	return ctx(3, integer(0), ctx(0, oid(oidPBKDF2)), algID("2.16.840.1.101.3.4.1.45"), octets(make([]byte, 40)))
}

func envelopedData(content string, recipients ...[]byte) []byte {
	eci := seq(oid(oidData), algID(content, octets(make([]byte, 16))), tlv(2, 0, false, make([]byte, 32)))
	return contentInfo(oidEnvelopedData, seq(integer(2), set(recipients...), eci))
}

func pbes2(cipher string) []byte {
	return algID(oidPBES2, seq(algID(oidPBKDF2, seq(octets(make([]byte, 8)), integer(2048))), algID(cipher, octets(make([]byte, 16)))))
}

// OpenPGP

func pgpPkt(tag int, body []byte) []byte {
	out := []byte{0xC0 | byte(tag)}
	switch l := len(body); {
	case l < 192:
		out = append(out, byte(l))
	case l < 8384:
		l -= 192
		out = append(out, byte(l>>8)+192, byte(l))
	default:
		out = append(out, 255, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	}
	return append(out, body...)
}

func mpi(bits int) []byte {
	n := (bits + 7) / 8
	b := make([]byte, 2+n)
	binary.BigEndian.PutUint16(b, uint16(bits))
	b[2] = 0x80 >> ((8 - bits%8) % 8)
	return b
}

func pkeskV3(algo int) []byte {
	return pgpPkt(1, append([]byte{3, 1, 2, 3, 4, 5, 6, 7, 8, byte(algo)}, mpi(2048)...))
}

func pkeskV6(algo int) []byte {
	return pgpPkt(1, append([]byte{6, 0, byte(algo)}, make([]byte, 64)...))
}

func skeskV4(sym int) []byte {
	return pgpPkt(3, []byte{4, byte(sym), 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 96})
}

func seipdV1() []byte { return pgpPkt(18, append([]byte{1}, make([]byte, 40)...)) }
func seipdV2(sym int) []byte {
	return pgpPkt(18, append([]byte{2, byte(sym), 2, 6}, make([]byte, 64)...))
}

var curve25519OID = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}

func rsaKeyV4(tag, bits int, secretUsage int) []byte {
	body := append([]byte{4, 0, 0, 0, 1, 1}, mpi(bits)...)
	body = append(body, mpi(17)...)
	if tag == 5 || tag == 7 {
		body = append(body, byte(secretUsage))
		if secretUsage == 254 {
			body = append(body, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 96)
		}
		body = append(body, make([]byte, 20)...)
	}
	return pgpPkt(tag, body)
}

func ecdhSubkeyV4() []byte {
	body := []byte{4, 0, 0, 0, 1, 18, byte(len(curve25519OID))}
	body = append(body, curve25519OID...)
	body = append(body, mpi(263)...)
	body = append(body, 3, 1, 8, 9)
	return pgpPkt(14, body)
}

func v6Key(tag, algo, materialLen int) []byte {
	body := []byte{6, 0, 0, 0, 1, byte(algo), 0, 0, 0, 0}
	binary.BigEndian.PutUint32(body[6:], uint32(materialLen))
	return pgpPkt(tag, append(body, make([]byte, materialLen)...))
}

func armorPGP(label string, data []byte) string {
	b := base64.StdEncoding.EncodeToString(data)
	var lines []string
	for len(b) > 64 {
		lines = append(lines, b[:64])
		b = b[64:]
	}
	lines = append(lines, b)
	return "-----BEGIN " + label + "-----\nComment: test\n\n" + strings.Join(lines, "\n") + "\n=AbCd\n-----END " + label + "-----\n"
}

// age

func ageFile(stanzas ...string) []byte {
	var b strings.Builder
	b.WriteString(ageMagic)
	for _, s := range stanzas {
		b.WriteString("-> " + s + "\n")
		b.WriteString("bm90IGEgcmVhbCBib2R5\n")
	}
	b.WriteString("--- aGVhZGVyIG1hYw\n")
	b.WriteString("\x00\x01binary payload")
	return []byte(b.String())
}

// JOSE

func jose(header string, parts int) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	out := []string{h}
	for i := 1; i < parts; i++ {
		out = append(out, base64.RawURLEncoding.EncodeToString([]byte("part")))
	}
	return strings.Join(out, ".")
}

// SSH

func sshStr(s []byte) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func sshEd25519Blob() []byte {
	return append(sshStr([]byte("ssh-ed25519")), sshStr(make([]byte, 32))...)
}

func sshRSABlob(bits int) []byte {
	n := make([]byte, bits/8+1)
	n[1] = 0x80
	return append(append(sshStr([]byte("ssh-rsa")), sshStr([]byte{1, 0, 1})...), sshStr(n)...)
}

func opensshKey(cipher string) []byte {
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = append(b, sshStr([]byte(cipher))...)
	kdf := "none"
	if cipher != "none" {
		kdf = "bcrypt"
	}
	b = append(b, sshStr([]byte(kdf))...)
	b = append(b, sshStr(nil)...)
	b = append(b, 0, 0, 0, 1)
	b = append(b, sshStr(sshEd25519Blob())...)
	b = append(b, sshStr(make([]byte, 64))...)
	return b
}
