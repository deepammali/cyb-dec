package inspect

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// OpenPGP (RFC 9580; post-quantum algorithms from RFC 9980).

type pgpPub struct {
	name      string
	primitive string
	enc       bool // can encrypt: data encrypted to it depends on it
	pq        bool
}

var pgpPubAlgs = map[int]pgpPub{
	1:  {"RSA", "key-transport", true, false},
	2:  {"RSA (encrypt-only)", "key-transport", true, false},
	3:  {"RSA (sign-only)", "signature", false, false},
	16: {"ElGamal", "key-transport", true, false},
	17: {"DSA", "signature", false, false},
	18: {"ECDH", "key-agree", true, false},
	19: {"ECDSA", "signature", false, false},
	20: {"ElGamal (legacy sign+encrypt)", "key-transport", true, false},
	22: {"EdDSA (legacy)", "signature", false, false},
	25: {"X25519", "key-agree", true, false},
	26: {"X448", "key-agree", true, false},
	27: {"Ed25519", "signature", false, false},
	28: {"Ed448", "signature", false, false},
	30: {"ML-DSA-65+Ed25519", "signature", false, true},
	31: {"ML-DSA-87+Ed448", "signature", false, true},
	32: {"SLH-DSA-SHAKE-128s", "signature", false, true},
	33: {"SLH-DSA-SHAKE-128f", "signature", false, true},
	34: {"SLH-DSA-SHAKE-256s", "signature", false, true},
	35: {"ML-KEM-768+X25519", "kem", true, true},
	36: {"ML-KEM-1024+X448", "kem", true, true},
}

func pgpPubAlg(id int) pgpPub {
	if a, ok := pgpPubAlgs[id]; ok {
		return a
	}
	return pgpPub{name: fmt.Sprintf("unknown public-key algorithm %d", id)}
}

type pgpSym struct {
	name   string
	bits   int
	legacy bool
}

var pgpSymAlgs = map[int]pgpSym{
	0: {"plaintext", 0, true}, 1: {"IDEA", 128, true}, 2: {"TripleDES", 168, true}, 3: {"CAST5", 128, true},
	4: {"Blowfish", 128, true}, 7: {"AES-128", 128, false}, 8: {"AES-192", 192, false}, 9: {"AES-256", 256, false},
	10: {"Twofish", 256, false}, 11: {"Camellia-128", 128, false}, 12: {"Camellia-192", 192, false}, 13: {"Camellia-256", 256, false},
}

func pgpSymAlg(id int) pgpSym {
	if a, ok := pgpSymAlgs[id]; ok {
		return a
	}
	return pgpSym{name: fmt.Sprintf("unknown cipher %d", id)}
}

var pgpAEAD = map[int]string{1: "EAX", 2: "OCB", 3: "GCM"}

type pgpPacket struct {
	tag  int
	body []byte // may be short of the declared length when the file was read head-only
}

// pgpPackets splits b into OpenPGP packets. It stops at the first encrypted or
// literal data packet (what follows is content) or at a malformed header.
func pgpPackets(b []byte) []pgpPacket {
	var out []pgpPacket
	for len(b) > 0 && len(out) < 256 {
		h := b[0]
		if h&0x80 == 0 {
			break
		}
		var tag, l, p int
		partial := false
		if h&0x40 != 0 { // OpenPGP format
			tag = int(h & 0x3f)
			if len(b) < 2 {
				break
			}
			switch o := int(b[1]); {
			case o < 192:
				l, p = o, 2
			case o < 224:
				if len(b) < 3 {
					return out
				}
				l, p = (o-192)<<8+int(b[2])+192, 3
			case o == 255:
				if len(b) < 6 {
					return out
				}
				l, p = int(binary.BigEndian.Uint32(b[2:6])), 6
			default:
				l, p, partial = 1<<(o&0x1f), 2, true
			}
		} else { // legacy format
			tag = int(h>>2) & 0x0f
			switch h & 3 {
			case 0:
				if len(b) < 2 {
					return out
				}
				l, p = int(b[1]), 2
			case 1:
				if len(b) < 3 {
					return out
				}
				l, p = int(binary.BigEndian.Uint16(b[1:3])), 3
			case 2:
				if len(b) < 5 {
					return out
				}
				l, p = int(binary.BigEndian.Uint32(b[1:5])), 5
			default:
				l, p = len(b)-1, 1
			}
		}
		if tag == 0 || l < 0 {
			break
		}
		end := p + l
		if end > len(b) || end < p {
			end = len(b)
		}
		out = append(out, pgpPacket{tag: tag, body: b[p:end]})
		if tag == 9 || tag == 18 || tag == 20 || tag == 11 || tag == 8 || partial {
			break
		}
		b = b[end:]
	}
	return out
}

// looksLikePGP reports whether b starts with a plausible OpenPGP packet that
// this package would describe. It guards binary sniffing against false hits.
func looksLikePGP(b []byte) bool {
	pk := pgpPackets(b)
	if len(pk) == 0 {
		return false
	}
	first := pk[0]
	if len(first.body) == 0 {
		return false
	}
	v := int(first.body[0])
	switch first.tag {
	case 1: // PKESK
		return v == 3 || v == 6
	case 3: // SKESK
		return v == 4 || v == 5 || v == 6
	case 5, 6: // secret/public key
		return v == 4 || v == 6 || v == 3
	case 2: // signature
		return v == 4 || v == 6 || v == 3
	case 4: // one-pass signature
		return v == 3 || v == 6
	}
	return false
}

// pgpFindings describes one OpenPGP artifact (a binary file or one armored block).
func pgpFindings(path string, b []byte, armor string) []Finding {
	pk := pgpPackets(b)
	if len(pk) == 0 {
		return nil
	}
	switch pk[0].tag {
	case 1, 3:
		return []Finding{pgpMessage(path, pk, armor)}
	case 5, 6:
		return []Finding{pgpKey(path, pk, armor)}
	case 2, 4:
		if f, ok := pgpSignature(path, pk, armor); ok {
			return []Finding{f}
		}
	}
	return nil
}

func pgpFormat(kind, armor string) string {
	if armor != "" {
		return "OpenPGP " + kind + " (armored)"
	}
	return "OpenPGP " + kind
}

func pgpMessage(path string, pk []pgpPacket, armor string) Finding {
	f := Finding{Path: path, Format: pgpFormat("encrypted message", armor), Confidence: "confirmed"}
	var classical, pq []string
	var passwords []pgpSym
	var sealed string // how the data packet protects content
	var bulk pgpSym
	for _, p := range pk {
		b := p.body
		switch p.tag {
		case 1: // PKESK
			if len(b) < 1 {
				continue
			}
			var algo int
			var who string
			switch b[0] {
			case 3:
				if len(b) < 10 {
					continue
				}
				algo = int(b[9])
				who = "key ID " + strings.ToUpper(hex.EncodeToString(b[1:9]))
				if who == "key ID 0000000000000000" {
					who = "hidden recipient"
				}
			case 6:
				if len(b) < 2 || len(b) < 2+int(b[1])+1 {
					continue
				}
				n := int(b[1])
				if n > 1 {
					who = "fingerprint " + strings.ToUpper(hex.EncodeToString(b[3:2+n]))
				} else {
					who = "hidden recipient"
				}
				algo = int(b[2+n])
			default:
				continue
			}
			a := pgpPubAlg(algo)
			f.fact("Recipient", fmt.Sprintf("%s (%s)", a.name, who))
			f.algo(Algorithm{Name: a.name, Primitive: a.primitive, Role: "recipient", PQ: a.pq})
			if a.pq {
				pq = append(pq, a.name)
			} else {
				classical = append(classical, a.name)
			}
		case 3: // SKESK
			if len(b) < 2 {
				continue
			}
			var s pgpSym
			switch b[0] {
			case 4:
				s = pgpSymAlg(int(b[1]))
			case 5: // LibrePGP: version, cipher, AEAD, S2K
				s = pgpSymAlg(int(b[1]))
			case 6: // version, field count, cipher, AEAD, S2K
				if len(b) < 3 {
					continue
				}
				s = pgpSymAlg(int(b[2]))
			default:
				continue
			}
			passwords = append(passwords, s)
			f.fact("Password", fmt.Sprintf("S2K-derived key, %s (SKESK v%d)", s.name, b[0]))
			f.algo(Algorithm{Name: s.name, Primitive: "cipher", Role: "key protection", PQ: !s.legacy, Bits: s.bits})
		case 18: // SEIPD
			if len(b) >= 1 && b[0] == 1 {
				sealed = "integrity-protected (SEIPD v1, MDC)"
			} else if len(b) >= 3 && b[0] == 2 {
				bulk = pgpSymAlg(int(b[1]))
				sealed = fmt.Sprintf("%s-%s AEAD (SEIPD v2)", bulk.name, orUnknown(pgpAEAD[int(b[2])]))
			}
		case 9:
			sealed = "no integrity protection (SED packet)"
			f.flag(FlagNoIntegrity)
		case 20:
			if len(b) >= 3 {
				bulk = pgpSymAlg(int(b[1]))
				sealed = fmt.Sprintf("%s-%s AEAD (LibrePGP OCB packet)", bulk.name, orUnknown(pgpAEAD[int(b[2])]))
			}
		}
	}
	f.fact("Data", sealed)
	if bulk.name != "" {
		f.algo(Algorithm{Name: bulk.name, Primitive: "cipher", Role: "content", PQ: !bulk.legacy, Bits: bulk.bits})
	}

	switch {
	case len(classical) > 0:
		f.Class = ClassExposed
		f.flag(FlagClassicalRecipient)
		f.Protection = strings.Join(uniq(append(classical, pq...)), " + ") + " → session key"
		f.Headline = fmt.Sprintf("Encrypted to %s. Anyone who keeps a copy can decrypt it once a quantum computer breaks %s.",
			strings.Join(uniq(classical), " and "), strings.Join(uniq(baseNames(classical)), " and "))
		if len(pq) > 0 {
			f.Headline += " The ML-KEM recipient doesn't help: any one recipient's key opens the message."
		}
	case len(pq) > 0:
		f.Class = ClassPQ
		f.Protection = strings.Join(uniq(pq), " + ") + " → session key"
		f.Headline = fmt.Sprintf("Encrypted to %s only: not exposed to harvest-now-decrypt-later.", strings.Join(uniq(pq), " and "))
	default:
		f.Class = ClassSymmetric
		f.Protection = "password"
		f.Headline = "Encrypted with a password only. No public-key step for a quantum computer to break; strength rests on the password."
	}
	for _, s := range append(passwords, bulk) {
		if s.name == "" {
			continue
		}
		if s.legacy {
			f.flag(FlagLegacyCipher)
		} else if s.bits == 128 {
			f.flag(FlagAES128)
		}
	}
	if f.Class != ClassExposed && (f.has(FlagLegacyCipher) || f.has(FlagNoIntegrity)) {
		f.Class = ClassWeak
		f.Headline = "Uses a legacy OpenPGP cipher or no integrity protection: re-encrypt with a current implementation."
	}
	if bulk.name != "" {
		f.Protection += " · " + bulk.name
	} else if len(passwords) > 0 {
		f.Protection += " · " + passwords[0].name
	}
	if len(pk) > 0 && bulk.name == "" && len(classical)+len(pq) > 0 {
		f.Limits = "The content cipher is inside the encrypted session key (SEIPD v1), so it isn't visible without the private key."
	}
	return f
}

// pgpKeyInfo parses the public part of a key packet.
type pgpKeyInfo struct {
	version int
	algo    pgpPub
	detail  string // "RSA 3072", "ECDH Curve25519"
	bits    int
	pubLen  int // length of the public part within the body
	fpr     string
}

func pgpParseKey(b []byte) (pgpKeyInfo, bool) {
	if len(b) < 6 {
		return pgpKeyInfo{}, false
	}
	k := pgpKeyInfo{version: int(b[0])}
	var id, p int // algorithm ID, and where the key material starts
	switch k.version {
	case 3: // version, created(4), validity(2), algorithm
		if len(b) < 8 {
			return k, false
		}
		id, p = int(b[7]), 8
	case 4: // version, created(4), algorithm
		id, p = int(b[5]), 6
	case 6: // version, created(4), algorithm, material length(4)
		if len(b) < 10 {
			return k, false
		}
		id, p = int(b[5]), 10
	default:
		return k, false
	}
	k.algo = pgpPubAlg(id)
	k.detail = k.algo.name
	start := p
	mpi := func() (int, bool) {
		if p+2 > len(b) {
			return 0, false
		}
		bits := int(binary.BigEndian.Uint16(b[p:]))
		p += 2 + (bits+7)/8
		return bits, p <= len(b)
	}
	curve := func() bool {
		if p >= len(b) {
			return false
		}
		n := int(b[p])
		if p+1+n > len(b) {
			return false
		}
		oid := oidBytes(b[p+1 : p+1+n])
		name := curves[oid]
		if name == "" {
			name = "curve " + oid
		}
		k.detail += " " + name
		p += 1 + n
		return true
	}
	ok := true
	switch id {
	case 1, 2, 3:
		k.bits, ok = mpi()
		if ok {
			_, ok = mpi()
		}
		k.detail = fmt.Sprintf("%s %d", k.algo.name, k.bits)
	case 16, 20:
		k.bits, ok = mpi()
		for i := 0; ok && i < 2; i++ {
			_, ok = mpi()
		}
		k.detail = fmt.Sprintf("%s %d", k.algo.name, k.bits)
	case 17:
		k.bits, ok = mpi()
		for i := 0; ok && i < 3; i++ {
			_, ok = mpi()
		}
		k.detail = fmt.Sprintf("%s %d", k.algo.name, k.bits)
	case 19, 22:
		ok = curve()
		if ok {
			_, ok = mpi()
		}
	case 18:
		ok = curve()
		if ok {
			_, ok = mpi()
		}
		if ok && p < len(b) {
			p += 1 + int(b[p])
		}
	default:
		if n, fixed := map[int]int{25: 32, 26: 56, 27: 32, 28: 57, 30: 32 + 1952, 31: 57 + 2592, 32: 32, 33: 32, 34: 64, 35: 32 + 1184, 36: 56 + 1568}[id]; fixed {
			p += n
		} else if k.version != 6 {
			ok = false
		}
	}
	if k.version == 6 {
		p = start + int(binary.BigEndian.Uint32(b[6:10]))
	}
	if !ok || p > len(b) {
		k.pubLen = -1
		return k, true
	}
	k.pubLen = p
	pub := b[:p]
	switch k.version {
	case 4:
		h := sha1.New()
		h.Write([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))})
		h.Write(pub)
		k.fpr = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	case 6:
		h := sha256.New()
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(pub)))
		h.Write([]byte{0x9b})
		h.Write(l[:])
		h.Write(pub)
		k.fpr = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	}
	return k, true
}

// pgpSecretProtection reads the S2K usage octet after the public part.
func pgpSecretProtection(b []byte, k pgpKeyInfo) (desc string, plain bool, sym pgpSym) {
	if k.pubLen < 0 || k.pubLen >= len(b) {
		return "", false, pgpSym{}
	}
	usage := int(b[k.pubLen])
	q := k.pubLen + 1
	if k.version == 6 && usage != 0 {
		q++ // count of the following fields
	}
	switch usage {
	case 0:
		return "not encrypted", true, pgpSym{}
	case 253, 254, 255:
		if q < len(b) {
			sym = pgpSymAlg(int(b[q]))
			return "passphrase, " + sym.name, false, sym
		}
		return "passphrase", false, pgpSym{}
	default:
		sym = pgpSymAlg(usage)
		return "passphrase, " + sym.name + " (legacy)", false, sym
	}
}

func pgpKey(path string, pk []pgpPacket, armor string) Finding {
	secret := pk[0].tag == 5
	kind := "public key"
	if secret {
		kind = "secret key"
	}
	f := Finding{Path: path, Format: pgpFormat(kind, armor), Confidence: "confirmed"}
	type keyPkt struct {
		p   pgpPacket
		k   pgpKeyInfo
		sub bool
	}
	var keys []keyPkt
	users := 0
	encSubkeys := false
	for _, p := range pk {
		switch p.tag {
		case 13:
			users++
		case 5, 6, 7, 14:
			if k, ok := pgpParseKey(p.body); ok {
				sub := p.tag == 7 || p.tag == 14
				keys = append(keys, keyPkt{p, k, sub})
				encSubkeys = encSubkeys || sub && k.algo.enc
			}
		}
	}
	var classicalEnc, pqEnc, classicalSig, pqSig []string
	for _, kp := range keys {
		k := kp.k
		role, use := "Primary key", "certification and signing"
		if kp.sub {
			role, use = "Subkey", "signing"
		}
		enc := k.algo.enc && (kp.sub || !encSubkeys)
		if enc {
			use = "encryption"
			if !kp.sub {
				use = "certification, signing, and encryption"
			}
		}
		line := fmt.Sprintf("%s (v%d, %s)", k.detail, k.version, use)
		if kp.p.tag == 5 || kp.p.tag == 7 {
			desc, plain, sym := pgpSecretProtection(kp.p.body, k)
			if desc != "" {
				line += ", secret " + desc
			}
			if plain {
				f.flag(FlagPlainPrivateKey)
			}
			if sym.legacy {
				f.flag(FlagLegacyCipher)
			}
		}
		f.fact(role, line)
		if !kp.sub && k.fpr != "" {
			f.fact("Fingerprint", k.fpr)
		}
		prim := k.algo.primitive
		if !enc && prim != "signature" {
			prim = "signature"
		}
		f.algo(Algorithm{Name: k.algo.name, Primitive: prim, Role: "public key", PQ: k.algo.pq, Bits: k.bits})
		switch {
		case enc && k.algo.pq:
			pqEnc = append(pqEnc, k.detail)
		case enc:
			classicalEnc = append(classicalEnc, k.detail)
		case k.algo.pq:
			pqSig = append(pqSig, k.detail)
		default:
			classicalSig = append(classicalSig, k.detail)
		}
	}
	if users > 0 {
		f.fact("User IDs", fmt.Sprint(users))
	}
	all := append(append(append(append([]string{}, classicalEnc...), pqEnc...), classicalSig...), pqSig...)
	f.Protection = strings.Join(uniq(all), " + ")
	switch {
	case len(classicalEnc) > 0:
		f.Class = ClassInventory
		f.flag(FlagClassicalKey, FlagClassicalEncKey)
		f.Headline = fmt.Sprintf("Classical encryption key (%s): everything encrypted to it is exposed to harvest-now-decrypt-later.", strings.Join(uniq(classicalEnc), ", "))
	case len(pqEnc) > 0 && len(classicalSig) > 0:
		f.Class = ClassPQ
		f.flag(FlagClassicalKey)
		f.Headline = fmt.Sprintf("Encryption uses %s (post-quantum); signatures are still classical (%s).", strings.Join(uniq(pqEnc), ", "), strings.Join(uniq(classicalSig), ", "))
	case len(pqEnc) > 0 || (len(pqSig) > 0 && len(classicalSig) == 0):
		f.Class = ClassPQ
		f.Headline = "Post-quantum key: " + f.Protection + "."
	default:
		f.Class = ClassInventory
		f.flag(FlagClassicalKey)
		f.Headline = fmt.Sprintf("Classical signing key (%s): not a harvest-now-decrypt-later risk, but it must migrate to ML-DSA.", f.Protection)
	}
	if f.has(FlagPlainPrivateKey) {
		f.Headline += " The secret key is stored without a passphrase."
	}
	return f
}

func pgpSignature(path string, pk []pgpPacket, armor string) (Finding, bool) {
	for _, p := range pk {
		b := p.body
		var algo int
		switch {
		case p.tag == 2 && len(b) >= 4 && (b[0] == 4 || b[0] == 6):
			algo = int(b[2])
		case p.tag == 2 && len(b) >= 16 && b[0] == 3:
			algo = int(b[15])
		case p.tag == 4 && len(b) >= 4:
			algo = int(b[3])
		default:
			continue
		}
		a := pgpPubAlg(algo)
		f := Finding{Path: path, Format: pgpFormat("signature", armor), Confidence: "confirmed", Protection: a.name}
		f.fact("Signature", a.name)
		f.algo(Algorithm{Name: a.name, Primitive: "signature", Role: "signature", PQ: a.pq})
		if a.pq {
			f.Class = ClassPQ
			f.Headline = "Post-quantum signature (" + a.name + ")."
		} else {
			f.Class = ClassInventory
			f.flag(FlagClassicalKey)
			f.Headline = "Classical signature (" + a.name + "): valid today; signers need to migrate to ML-DSA."
		}
		return f, true
	}
	return Finding{}, false
}

// baseNames drops parenthesized detail: "ECDH (SHA-1 KDF)" → "ECDH".
func baseNames(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		if j := strings.Index(s, " ("); j > 0 {
			s = s[:j]
		}
		out[i] = s
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
