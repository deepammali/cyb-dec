package inspect

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Keys and certificates: X.509, SPKI, PKCS#8 (plain and encrypted), PKCS#1,
// SEC1, OpenSSH private and public keys, Java key stores, and age identities
// and recipients. Classical keys are migration inventory: they are not data,
// but anything encrypted to a classical encryption key is exposed.

// keyDesc names a SubjectPublicKeyInfo or PrivateKeyInfo algorithm with its size or curve.
type keyDesc struct {
	a      alg
	detail string // "RSA 2048", "EC P-256", "ML-DSA-65"
	bits   int
}

func describeKey(algID node, keyBits []byte, keyIsPrivate bool) keyDesc {
	oid, params := algID.algorithm()
	d := keyDesc{a: lookup(oid)}
	d.detail = d.a.name
	switch oid {
	case oidECPublicKey:
		if len(params) > 0 {
			name := curves[params[0].oid()]
			if name == "" {
				name = "named curve " + params[0].oid()
			}
			d.detail = "EC " + name
		}
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
		body := keyBits
		idx := 0
		if keyIsPrivate {
			idx = 1 // RSAPrivateKey: version, modulus, ...
		} else if len(body) > 0 {
			body = body[1:] // BIT STRING: unused-bits octet
		}
		if seq, _, err := parseNode(body); err == nil {
			d.bits = rsaBits(seq, idx)
		}
		if d.bits > 0 {
			d.detail = fmt.Sprintf("RSA %d", d.bits)
		}
	}
	return d
}

func (d keyDesc) encryption() bool {
	return d.a.primitive == "key-agree" || d.a.primitive == "kem" || d.a.primitive == "key-transport"
}

// keyFinding fills in the class for a single key.
func keyFinding(f Finding, d keyDesc, what string) Finding {
	f.Protection = d.detail
	f.fact("Key", d.detail)
	name := d.a.name
	if strings.HasPrefix(d.detail, "EC ") {
		name = d.detail // the curve matters for an EC key
	}
	f.algo(Algorithm{Name: name, Primitive: d.a.primitive, Role: "public key", PQ: d.a.pq, Bits: d.bits})
	switch {
	case d.a.pq:
		f.Class = ClassPQ
		f.Headline = fmt.Sprintf("Post-quantum %s (%s).", what, d.detail)
	case strings.HasPrefix(d.a.name, "unrecognized"):
		f.Class = ClassInventory
		f.Confidence = "low"
		f.Headline = fmt.Sprintf("%s with an algorithm pqscan doesn't recognize (%s).", upperFirst(what), d.detail)
	default:
		f.Class = ClassInventory
		f.flag(FlagClassicalKey)
		f.Headline = fmt.Sprintf("Classical %s (%s): Shor's algorithm breaks it at any size; plan its replacement.", what, d.detail)
		if d.encryption() {
			f.flag(FlagClassicalEncKey)
			f.Headline = fmt.Sprintf("Classical key-establishment %s (%s): everything encrypted to it is exposed to harvest-now-decrypt-later.", what, d.detail)
		}
		if d.a.name == "RSA" && d.bits > 0 && d.bits < 2048 || d.a.name == "DSA" {
			f.flag(FlagLegacyCipher)
			f.Class = ClassWeak
			f.Headline = fmt.Sprintf("%s is too weak today (%s), quantum computers aside.", upperFirst(what), d.detail)
		}
	}
	return f
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// certFinding describes an X.509 certificate. ok is false when n isn't one.
func certFinding(path string, n node) (Finding, bool) {
	c := n.children()
	if len(c) != 3 || !c[0].isSeq() || !c[1].isSeq() || !c[2].is(classUniversal, 3) {
		return Finding{}, false
	}
	tbs := c[0].children()
	off := 0
	if len(tbs) > 0 && tbs[0].is(classContext, 0) {
		off = 1
	}
	if len(tbs) < off+6 || !tbs[off+5].isSeq() {
		return Finding{}, false
	}
	spki := tbs[off+5].children()
	if len(spki) < 2 {
		return Finding{}, false
	}
	d := describeKey(spki[0], spki[1].body, false)
	sigOID, _ := c[1].algorithm()
	sig := lookup(sigOID)
	f := Finding{Path: path, Format: "X.509 certificate", Confidence: "confirmed"}
	if cert, err := x509.ParseCertificate(n.raw); err == nil {
		f.fact("Subject", cert.Subject.String())
		if cert.Issuer.String() != cert.Subject.String() {
			f.fact("Issuer", cert.Issuer.String())
		} else {
			f.fact("Issuer", "self-signed")
		}
		f.fact("Valid until", cert.NotAfter.UTC().Format(time.RFC3339))
		if u := keyUsage(cert.KeyUsage); u != "" {
			f.fact("Key usage", u)
		}
		if cert.IsCA {
			f.fact("CA", "yes")
		}
		f = keyFinding(f, d, "certificate key")
		if d.a.name == "RSA" && cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			f.flag(FlagClassicalEncKey)
			f.fact("Exposure", "keyEncipherment: RSA key transport to this key (TLS 1.2 RSA key exchange, S/MIME encryption) is harvest-now-decrypt-later exposed")
		}
	} else {
		f = keyFinding(f, d, "certificate key")
	}
	f.fact("Signed with", sig.name)
	f.algo(Algorithm{Name: sig.name, Primitive: "signature", Role: "signature", PQ: sig.pq})
	f.Protection = d.detail + " · signed " + sig.name
	return f, true
}

func keyUsage(u x509.KeyUsage) string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"}, {x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"},
	}
	var out []string
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return strings.Join(out, ", ")
}

// derKeyFinding recognizes the DER key structures. ok is false for none of them.
func derKeyFinding(path string, n node) (Finding, bool) {
	c := n.children()
	switch {
	case len(c) >= 3 && c[0].is(classUniversal, tagInteger) && c[1].isSeq() && c[2].is(classUniversal, tagOctetString):
		// PrivateKeyInfo (PKCS#8)
		d := describeKey(c[1], c[2].body, true)
		if d.a.name == "EC" || strings.HasPrefix(d.detail, "EC") {
			if sec1, _, err := parseNode(c[2].body); err == nil {
				for _, x := range sec1.children() {
					if x.is(classContext, 0) {
						if cc := x.children(); len(cc) > 0 && curves[cc[0].oid()] != "" {
							d.detail = "EC " + curves[cc[0].oid()]
						}
					}
				}
			}
		}
		f := Finding{Path: path, Format: "PKCS#8 private key", Confidence: "confirmed"}
		f = keyFinding(f, d, "private key")
		f.flag(FlagPlainPrivateKey)
		f.fact("Stored", "not encrypted")
		return f, true
	case len(c) == 2 && c[0].isSeq() && c[1].is(classUniversal, tagOctetString):
		// EncryptedPrivateKeyInfo
		oid, _ := c[0].algorithm()
		if a := lookup(oid); a.primitive != "pbe" && oid != oidPBES2 {
			return Finding{}, false
		}
		desc, a := pbeDesc(c[0])
		f := Finding{Path: path, Format: "Encrypted PKCS#8 private key", Confidence: "high", Class: ClassInventory, Protection: desc}
		f.fact("Key protection", desc)
		f.algo(Algorithm{Name: a.name, Primitive: "pbe", Role: "key protection", PQ: a.pq, Bits: a.bits})
		f.Limits = "The key's own algorithm is encrypted and can't be read without the password."
		if a.legacy {
			f.flag(FlagLegacyCipher)
			f.Class = ClassWeak
			f.Headline = "Private key encrypted with a legacy scheme (" + desc + "): re-encrypt it with PBES2 and AES-256."
		} else {
			f.flag(FlagClassicalKey)
			f.Headline = "Encrypted private key (" + desc + "). Its algorithm is hidden; it is classical unless it was generated as ML-DSA or ML-KEM."
		}
		return f, true
	case len(c) == 2 && c[0].isSeq() && c[1].is(classUniversal, 3):
		// SubjectPublicKeyInfo
		d := describeKey(c[0], c[1].body, false)
		if d.a.primitive == "" {
			return Finding{}, false
		}
		return keyFinding(Finding{Path: path, Format: "Public key", Confidence: "confirmed"}, d, "public key"), true
	case len(c) >= 9 && c[0].is(classUniversal, tagInteger) && c[1].is(classUniversal, tagInteger):
		// RSAPrivateKey (PKCS#1)
		d := keyDesc{a: oids["1.2.840.113549.1.1.1"], bits: rsaBits(n, 1)}
		d.detail = fmt.Sprintf("RSA %d", d.bits)
		f := keyFinding(Finding{Path: path, Format: "RSA private key (PKCS#1)", Confidence: "confirmed"}, d, "private key")
		f.flag(FlagPlainPrivateKey)
		f.fact("Stored", "not encrypted")
		return f, true
	case len(c) >= 2 && c[0].is(classUniversal, tagInteger) && len(c[0].body) == 1 && c[0].body[0] == 1 && c[1].is(classUniversal, tagOctetString):
		// ECPrivateKey (SEC 1)
		d := keyDesc{a: oids[oidECPublicKey], detail: "EC"}
		for _, x := range c[2:] {
			if x.is(classContext, 0) {
				if cc := x.children(); len(cc) > 0 {
					d.detail = "EC " + orUnknown(curves[cc[0].oid()])
				}
			}
		}
		f := keyFinding(Finding{Path: path, Format: "EC private key (SEC 1)", Confidence: "confirmed"}, d, "private key")
		f.flag(FlagPlainPrivateKey)
		f.fact("Stored", "not encrypted")
		return f, true
	}
	return Finding{}, false
}

// csrFinding describes a PKCS#10 certificate request.
func csrFinding(path string, der []byte) (Finding, bool) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return Finding{}, false
	}
	n, _, err := parseNode(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return Finding{}, false
	}
	c := n.children()
	if len(c) < 2 {
		return Finding{}, false
	}
	f := keyFinding(Finding{Path: path, Format: "Certificate request (PKCS#10)", Confidence: "confirmed"}, describeKey(c[0], c[1].body, false), "certificate request key")
	f.fact("Subject", csr.Subject.String())
	return f, true
}

// legacyPEMFinding handles "RSA/EC/DSA PRIVATE KEY" PEM blocks, including the
// legacy Proc-Type/DEK-Info encryption.
func legacyPEMFinding(path string, b *pem.Block) (Finding, bool) {
	if b.Headers["Proc-Type"] == "4,ENCRYPTED" {
		algo := strings.Split(b.Headers["DEK-Info"], ",")[0]
		kind := strings.TrimSuffix(b.Type, " PRIVATE KEY")
		f := Finding{Path: path, Format: "Encrypted " + kind + " private key (legacy PEM)", Confidence: "confirmed", Protection: kind + " · " + algo}
		f.fact("Key", kind)
		f.fact("Key protection", algo+", key derived with one MD5 pass (OpenSSL legacy PEM)")
		f.algo(Algorithm{Name: algo, Primitive: "cipher", Role: "key protection", PQ: !strings.Contains(algo, "DES")})
		f.flag(FlagLegacyCipher, FlagClassicalKey)
		f.Class = ClassWeak
		f.Headline = "Private key encrypted with the legacy PEM scheme (" + algo + " with a single-pass MD5 key derivation): the passphrase is cheap to brute-force. Convert it to PKCS#8 with PBES2."
		return f, true
	}
	if b.Type == "DSA PRIVATE KEY" {
		f := keyFinding(Finding{Path: path, Format: "DSA private key", Confidence: "confirmed"}, keyDesc{a: oids["1.2.840.10040.4.1"], detail: "DSA"}, "private key")
		f.flag(FlagPlainPrivateKey)
		return f, true
	}
	n, _, err := parseNode(b.Bytes)
	if err != nil {
		return Finding{}, false
	}
	return derKeyFinding(path, n)
}

// OpenSSH private keys ("openssh-key-v1").

func sshString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint32(b))
	if n < 0 || 4+n > len(b) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// sshKeyDesc describes an SSH public key blob.
func sshKeyDesc(blob []byte) (string, keyDesc, bool) {
	t, rest, ok := sshString(blob)
	if !ok {
		return "", keyDesc{}, false
	}
	typ := string(t)
	d := keyDesc{detail: typ}
	switch {
	case strings.HasPrefix(typ, "ssh-rsa"):
		_, rest, ok = sshString(rest) // e
		if !ok {
			return typ, d, false
		}
		n, _, ok := sshString(rest)
		if !ok {
			return typ, d, false
		}
		for len(n) > 0 && n[0] == 0 {
			n = n[1:]
		}
		bits := 0
		if len(n) > 0 {
			bits = (len(n) - 1) * 8
			for x := n[0]; x > 0; x >>= 1 {
				bits++
			}
		}
		d = keyDesc{a: oids["1.2.840.113549.1.1.1"], bits: bits, detail: fmt.Sprintf("RSA %d", bits)}
	case strings.HasPrefix(typ, "ssh-ed25519"), strings.HasPrefix(typ, "sk-ssh-ed25519"):
		d = keyDesc{a: oids["1.3.101.112"], detail: "Ed25519"}
	case strings.HasPrefix(typ, "ssh-ed448"):
		d = keyDesc{a: oids["1.3.101.113"], detail: "Ed448"}
	case strings.HasPrefix(typ, "ecdsa-sha2-"), strings.HasPrefix(typ, "sk-ecdsa-sha2-"):
		curve := map[string]string{"nistp256": "P-256", "nistp384": "P-384", "nistp521": "P-521"}
		name := typ
		for k, v := range curve {
			if strings.Contains(typ, k) {
				name = v
			}
		}
		d = keyDesc{a: alg{name: "ECDSA", primitive: "signature"}, detail: "ECDSA " + name}
	case strings.HasPrefix(typ, "ssh-dss"):
		d = keyDesc{a: oids["1.2.840.10040.4.1"], detail: "DSA"}
	default:
		d.a = alg{name: typ}
		if strings.Contains(typ, "mldsa") || strings.Contains(typ, "ml-dsa") {
			d.a = alg{name: typ, primitive: "signature", pq: true}
		}
	}
	if d.a.primitive == "" && d.a.name != "" && !d.a.pq {
		d.a.primitive = "signature"
	}
	if d.a.name == "RSA" || d.a.name == "DSA" {
		d.a.primitive = "signature" // SSH user and host keys authenticate; they don't encrypt
	}
	return typ, d, true
}

func opensshKeyFinding(path string, b []byte) (Finding, bool) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return Finding{}, false
	}
	rest := b[len(magic):]
	cipher, rest, ok := sshString(rest)
	if !ok {
		return Finding{}, false
	}
	kdf, rest, ok := sshString(rest)
	if !ok {
		return Finding{}, false
	}
	_, rest, ok = sshString(rest) // kdf options
	if !ok || len(rest) < 4 {
		return Finding{}, false
	}
	rest = rest[4:] // number of keys
	pub, _, ok := sshString(rest)
	if !ok {
		return Finding{}, false
	}
	_, d, ok := sshKeyDesc(pub)
	if !ok {
		return Finding{}, false
	}
	f := keyFinding(Finding{Path: path, Format: "OpenSSH private key", Confidence: "confirmed"}, d, "SSH key")
	if string(cipher) == "none" {
		f.flag(FlagPlainPrivateKey)
		f.fact("Stored", "not encrypted (no passphrase)")
	} else {
		f.fact("Key protection", fmt.Sprintf("%s, KDF %s", cipher, kdf))
	}
	return f, true
}

// SSH public key lines (authorized_keys, known_hosts, *.pub), aggregated per file.
var sshLineRE = regexp.MustCompile(`(?:^|[\s,])((?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)(?:-cert-v01@openssh\.com)?)\s+(AAAA[0-9A-Za-z+/]+={0,3})`)

func sshPublicKeyFindings(path string, text []byte) []Finding {
	type agg struct {
		d     keyDesc
		count int
	}
	found := map[string]*agg{}
	for _, m := range sshLineRE.FindAllSubmatch(text, 10000) {
		blob, err := base64.StdEncoding.DecodeString(string(m[2]))
		if err != nil {
			continue
		}
		typ, d, ok := sshKeyDesc(blob)
		if !ok || typ != string(m[1]) {
			continue
		}
		if found[d.detail] == nil {
			found[d.detail] = &agg{d: d}
		}
		found[d.detail].count++
	}
	format := "SSH public keys"
	base := path[strings.LastIndexAny(path, "/\\!")+1:]
	switch {
	case strings.HasPrefix(base, "authorized_keys"):
		format = "SSH authorized keys"
	case strings.HasPrefix(base, "known_hosts"):
		format = "SSH known host keys"
	}
	var out []Finding
	for _, k := range sortedKeys(found) {
		a := found[k]
		f := keyFinding(Finding{Path: path, Format: format, Confidence: "confirmed", Count: a.count}, a.d, "SSH key")
		if f.Class == ClassInventory {
			f.Headline = fmt.Sprintf("%d %s %s. SSH keys authenticate rather than encrypt, so they aren't a harvest-now-decrypt-later risk, but Shor's algorithm breaks them at any size: plan their replacement.",
				a.count, a.d.detail, plural(a.count, "key", "keys"))
		}
		out = append(out, f)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// age identities and recipients in text (key files, .sops.yaml, recipients files).
var (
	ageIdentityRE  = regexp.MustCompile(`AGE-SECRET-KEY-(PQ-)?1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{50,}`)
	ageRecipientRE = regexp.MustCompile(`\bage1(pq1|tagpq1|tag1)?[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,}`)
)

func ageKeyFindings(path string, text []byte) []Finding {
	var out []Finding
	ids := map[string]int{}
	for _, m := range ageIdentityRE.FindAllSubmatch(text, 1000) {
		ids[string(m[1])]++
	}
	for _, pq := range sortedKeys(ids) {
		n := ids[pq]
		f := Finding{Path: path, Format: "age identity (private key)", Confidence: "confirmed", Count: n}
		f.flag(FlagPlainPrivateKey)
		if pq != "" {
			f.Class, f.Protection = ClassPQ, "ML-KEM-768 + X25519"
			f.Headline = fmt.Sprintf("%d post-quantum age %s (ML-KEM-768 + X25519).", n, plural(n, "identity", "identities"))
			f.algo(Algorithm{Name: "ML-KEM-768+X25519", Primitive: "kem", Role: "public key", PQ: true})
		} else {
			f.Class, f.Protection = ClassInventory, "X25519"
			f.flag(FlagClassicalKey, FlagClassicalEncKey)
			f.Headline = fmt.Sprintf("%d X25519 age %s: files encrypted to %s are exposed to harvest-now-decrypt-later.", n, plural(n, "identity", "identities"), plural(n, "it", "them"))
			f.algo(Algorithm{Name: "X25519", Primitive: "key-agree", Role: "public key"})
		}
		f.fact("Stored", "plaintext key file")
		out = append(out, f)
	}
	recips := map[string]int{}
	if len(ids) == 0 { // in a key file, the "# public key:" line is the identity's own recipient
		for _, m := range ageRecipientRE.FindAllSubmatch(text, 1000) {
			recips[string(m[1])]++
		}
	}
	names := map[string]string{"": "X25519", "pq1": "ML-KEM-768 + X25519", "tag1": "P-256 (hardware tag)", "tagpq1": "ML-KEM-768 + P-256 (hardware tag)"}
	for _, kind := range sortedKeys(recips) {
		n := recips[kind]
		f := Finding{Path: path, Format: "age recipients", Confidence: "confirmed", Count: n, Protection: names[kind]}
		f.fact("Recipient type", names[kind])
		if strings.Contains(kind, "pq") {
			f.Class = ClassPQ
			f.Headline = fmt.Sprintf("%d post-quantum age %s (%s).", n, plural(n, "recipient", "recipients"), names[kind])
			f.algo(Algorithm{Name: names[kind], Primitive: "kem", Role: "recipient", PQ: true})
		} else {
			f.Class = ClassInventory
			f.flag(FlagClassicalKey, FlagClassicalEncKey)
			f.Headline = fmt.Sprintf("%d classical age %s (%s): anything encrypted to %s is exposed to harvest-now-decrypt-later.", n, plural(n, "recipient", "recipients"), names[kind], plural(n, "it", "them"))
			f.algo(Algorithm{Name: names[kind], Primitive: "key-agree", Role: "recipient"})
		}
		out = append(out, f)
	}
	return out
}

// Java key stores. JKS protects private keys with a proprietary SHA-1-based
// scheme and JCEKS with PBE-MD5-3DES; both are legacy.
func javaKeyStoreFinding(path string, b []byte) (Finding, bool) {
	if len(b) < 12 {
		return Finding{}, false
	}
	magic := binary.BigEndian.Uint32(b)
	var format, protection string
	switch magic {
	case 0xFEEDFEED:
		format, protection = "Java KeyStore (JKS)", "JKS proprietary key protection (SHA-1 based)"
	case 0xCECECECE:
		format, protection = "Java KeyStore (JCEKS)", "PBE-MD5-3DES"
	default:
		return Finding{}, false
	}
	version := binary.BigEndian.Uint32(b[4:])
	count := int(binary.BigEndian.Uint32(b[8:]))
	f := Finding{Path: path, Format: format, Confidence: "confirmed", Class: ClassWeak, Protection: protection}
	f.flag(FlagLegacyCipher)
	f.fact("Entries", fmt.Sprint(count))
	f.fact("Key protection", protection)
	f.algo(Algorithm{Name: protection, Primitive: "pbe", Role: "key protection"})

	// Walk the entries for the certificates' algorithms; stop at anything unexpected.
	p := 12
	u16 := func() (int, bool) {
		if p+2 > len(b) {
			return 0, false
		}
		v := int(binary.BigEndian.Uint16(b[p:]))
		p += 2
		return v, true
	}
	u32 := func() (int, bool) {
		if p+4 > len(b) {
			return 0, false
		}
		v := int(binary.BigEndian.Uint32(b[p:]))
		p += 4
		return v, v >= 0
	}
	var certKeys []string
	cert := func() bool {
		if version == 2 {
			n, ok := u16()
			if !ok || p+n > len(b) {
				return false
			}
			p += n // certificate type, "X.509"
		}
		n, ok := u32()
		if !ok || p+n > len(b) {
			return false
		}
		if node, _, err := parseNode(b[p : p+n]); err == nil {
			if cf, ok := certFinding(path, node); ok {
				certKeys = append(certKeys, cf.Protection)
				f.Algorithms = append(f.Algorithms, cf.Algorithms...)
			}
		}
		p += n
		return true
	}
entries:
	for i := 0; i < count && i < 1000; i++ {
		tag, ok := u32()
		if !ok {
			break
		}
		n, ok := u16() // alias
		if !ok || p+n+8 > len(b) {
			break
		}
		p += n + 8 // alias, timestamp
		switch tag {
		case 1: // private key entry
			n, ok := u32()
			if !ok || p+n > len(b) {
				break entries
			}
			p += n
			chain, ok := u32()
			if !ok {
				break entries
			}
			for j := 0; j < chain; j++ {
				if !cert() {
					break entries
				}
			}
		case 2: // trusted certificate
			if !cert() {
				break entries
			}
		default:
			break entries
		}
	}
	if len(certKeys) > 0 {
		counts := map[string]int{}
		for _, k := range certKeys {
			counts[k]++
		}
		var parts []string
		for _, k := range sortedKeys(counts) {
			parts = append(parts, fmt.Sprintf("%d× %s", counts[k], k))
		}
		f.fact("Certificates", strings.Join(parts, "; "))
		f.flag(FlagClassicalKey)
	}
	f.Headline = format + " protects private keys with " + protection + ", a legacy scheme. Convert it to PKCS#12 with AES-256."
	return f, true
}
