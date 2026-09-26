package inspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// inspectBytes runs the inspector over one in-memory file.
func inspectBytes(t *testing.T, name string, data []byte) Report {
	t.Helper()
	in := New(context.Background(), Options{}, nil)
	in.Bytes(name, data)
	return in.Report()
}

// one returns the single finding, failing otherwise.
func one(t *testing.T, r Report) Finding {
	t.Helper()
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v (skipped %+v)", len(r.Findings), r.Findings, r.Skipped)
	}
	return r.Findings[0]
}

func expect(t *testing.T, f Finding, class Class, flags ...string) {
	t.Helper()
	if f.Class != class {
		t.Errorf("%s: class %s, want %s (%s)", f.Format, f.Class, class, f.Headline)
	}
	for _, fl := range flags {
		if !f.has(fl) {
			t.Errorf("%s: missing flag %s (flags %v)", f.Format, fl, f.Flags)
		}
	}
}

func TestOpenPGPMessages(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		class Class
		flags []string
		prot  string
	}{
		{"rsa recipient", cat(pkeskV3(1), seipdV1()), ClassExposed, []string{FlagClassicalRecipient}, "RSA"},
		{"x25519 recipient, v6", cat(pkeskV6(25), seipdV2(9)), ClassExposed, []string{FlagClassicalRecipient}, "AES-256"},
		{"ml-kem only", cat(pkeskV6(35), seipdV2(9)), ClassPQ, nil, "ML-KEM-768+X25519"},
		{"ml-kem plus a classical recipient", cat(pkeskV6(35), pkeskV6(18), seipdV2(9)), ClassExposed, []string{FlagClassicalRecipient}, "ECDH"},
		{"password aes-256", cat(skeskV4(9), seipdV1()), ClassSymmetric, nil, "password"},
		{"password aes-128", cat(skeskV4(7), seipdV1()), ClassSymmetric, []string{FlagAES128}, "AES-128"},
		{"password cast5", cat(skeskV4(3), seipdV1()), ClassWeak, []string{FlagLegacyCipher}, "CAST5"},
		{"no integrity", cat(skeskV4(9), pgpPkt(9, make([]byte, 30))), ClassWeak, []string{FlagNoIntegrity}, ""},
		// GnuPG 2.4 writes the LibrePGP OCB packet (tag 20) by default.
		{"librepgp ocb", cat(pkeskV3(18), pgpPkt(20, append([]byte{1, 9, 2, 16}, make([]byte, 40)...))), ClassExposed, nil, "AES-256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := one(t, inspectBytes(t, "msg.gpg", tc.data))
			expect(t, f, tc.class, tc.flags...)
			if !strings.Contains(f.Protection, tc.prot) {
				t.Errorf("protection %q, want it to mention %q", f.Protection, tc.prot)
			}
			if f.Confidence != "confirmed" {
				t.Errorf("confidence %s", f.Confidence)
			}
		})
	}

	// Armored, embedded in a text file with other content.
	text := "notes\n" + armorPGP("PGP MESSAGE", cat(pkeskV3(1), seipdV1())) + "more notes\n"
	f := one(t, inspectBytes(t, "notes.txt", []byte(text)))
	expect(t, f, ClassExposed)
	if f.Format != "OpenPGP encrypted message (armored)" || !strings.Contains(f.Path, "#block 1") {
		t.Errorf("armored: format %q path %q", f.Format, f.Path)
	}
}

func TestOpenPGPKeys(t *testing.T) {
	pub := cat(rsaKeyV4(6, 3072, 0), pgpPkt(13, []byte("Alice <a@example.com>")), ecdhSubkeyV4())
	f := one(t, inspectBytes(t, "alice.pgp", pub))
	expect(t, f, ClassInventory, FlagClassicalKey, FlagClassicalEncKey)
	if !strings.Contains(f.Protection, "RSA 3072") || !strings.Contains(f.Protection, "ECDH Curve25519") {
		t.Errorf("protection %q", f.Protection)
	}
	for _, e := range f.Evidence {
		if strings.Contains(e.Value, "Alice") || strings.Contains(e.Value, "example.com") {
			t.Errorf("user IDs must not be reported: %+v", e)
		}
	}
	fpr := false
	for _, e := range f.Evidence {
		fpr = fpr || e.Label == "Fingerprint" && len(e.Value) == 40
	}
	if !fpr {
		t.Errorf("v4 fingerprint missing: %+v", f.Evidence)
	}

	// With an encryption subkey, the RSA primary only certifies; alone, it also encrypts.
	for _, e := range f.Evidence {
		if e.Label == "Primary key" && strings.Contains(e.Value, "encryption") {
			t.Errorf("primary with an encryption subkey labeled %q", e.Value)
		}
	}
	f = one(t, inspectBytes(t, "old.pgp", rsaKeyV4(6, 2048, 0)))
	expect(t, f, ClassInventory, FlagClassicalEncKey)

	// v6 Ed25519 primary with an ML-KEM-768+X25519 subkey (RFC 9980).
	pq := cat(v6Key(6, 27, 32), v6Key(14, 35, 32+1184))
	f = one(t, inspectBytes(t, "pq.pgp", pq))
	expect(t, f, ClassPQ, FlagClassicalKey)

	// Secret key without a passphrase.
	f = one(t, inspectBytes(t, "secret.pgp", rsaKeyV4(5, 2048, 0)))
	expect(t, f, ClassInventory, FlagPlainPrivateKey)
	f = one(t, inspectBytes(t, "secret2.pgp", rsaKeyV4(5, 2048, 254)))
	if f.has(FlagPlainPrivateKey) {
		t.Error("a protected secret key was reported as unprotected")
	}
}

func TestCMS(t *testing.T) {
	cases := []struct {
		name  string
		der   []byte
		class Class
		flags []string
	}{
		{"rsa-oaep", envelopedData("2.16.840.1.101.3.4.1.42", ktri("1.2.840.113549.1.1.7")), ClassExposed, []string{FlagClassicalRecipient}},
		{"ecdh", envelopedData("2.16.840.1.101.3.4.1.46", kari()), ClassExposed, []string{FlagClassicalRecipient}},
		{"ml-kem", envelopedData("2.16.840.1.101.3.4.1.46", kemri("2.16.840.1.101.3.4.4.2")), ClassPQ, nil},
		{"ml-kem + rsa", envelopedData("2.16.840.1.101.3.4.1.46", kemri("2.16.840.1.101.3.4.4.2"), ktri("1.2.840.113549.1.1.1")), ClassExposed, nil},
		{"password", envelopedData("2.16.840.1.101.3.4.1.42", pwri()), ClassSymmetric, nil},
		{"password, 3des", envelopedData("1.2.840.113549.3.7", pwri()), ClassWeak, []string{FlagLegacyCipher}},
		{"rsa, aes-128", envelopedData("2.16.840.1.101.3.4.1.2", ktri("1.2.840.113549.1.1.1")), ClassExposed, []string{FlagAES128}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := one(t, inspectBytes(t, "smime.p7m", tc.der))
			expect(t, f, tc.class, tc.flags...)
		})
	}

	// Read head-only: the recipients come before the content, so a truncated file still classifies.
	big := envelopedData("2.16.840.1.101.3.4.1.42", ktri("1.2.840.113549.1.1.1"))
	f := one(t, inspectBytes(t, "trunc.p7m", big[:len(big)-20]))
	expect(t, f, ClassExposed)

	// PEM-wrapped signed data.
	sd := contentInfo(oidSignedData, seq(integer(1), set(algID("2.16.840.1.101.3.4.2.1")), seq(oid(oidData)),
		set(seq(integer(1), issuerAndSerial(), algID("2.16.840.1.101.3.4.2.1"), algID("1.2.840.113549.1.1.11"), octets(make([]byte, 16))))))
	f = one(t, inspectBytes(t, "sig.pem", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: sd})))
	expect(t, f, ClassInventory, FlagClassicalKey)
	if f.Protection != "SHA256-RSA" {
		t.Errorf("signature %q", f.Protection)
	}
}

func TestPKCS12(t *testing.T) {
	cert, _ := ecCert(t)
	bags := seq(
		seq(oid(oidShroudedKeyBag), ctx(0, seq(pbes2("2.16.840.1.101.3.4.1.42"), octets(make([]byte, 48))))),
		seq(oid(oidCertBag), ctx(0, seq(oid("1.2.840.113549.1.9.22.1"), ctx(0, octets(cert))))),
	)
	legacy := seq(integer(0), seq(oid(oidData), algID("1.2.840.113549.1.12.1.6", seq(octets(make([]byte, 8)), integer(2048))), tlv(2, 0, false, make([]byte, 32))))
	pfx := func(parts ...[]byte) []byte {
		return seq(integer(3), contentInfo(oidData, octets(seq(parts...))), seq())
	}
	f := one(t, inspectBytes(t, "modern.p12", pfx(contentInfo(oidData, octets(bags)))))
	expect(t, f, ClassInventory, FlagClassicalKey)
	if !strings.Contains(f.Protection, "EC P-256") || !strings.Contains(f.Protection, "AES-256-CBC") {
		t.Errorf("protection %q", f.Protection)
	}
	f = one(t, inspectBytes(t, "legacy.p12", pfx(contentInfo(oidEncryptedData, legacy), contentInfo(oidData, octets(bags)))))
	expect(t, f, ClassWeak, FlagLegacyCipher)
}

func TestAge(t *testing.T) {
	x := "X25519 dGVzdA"
	pq := "mlkem768x25519 dGVzdA"
	cases := []struct {
		name  string
		data  []byte
		class Class
	}{
		{"x25519", ageFile(x), ClassExposed},
		{"ml-kem hybrid", ageFile(pq, pq), ClassPQ},
		{"mixed", ageFile(pq, x), ClassExposed},
		{"scrypt", ageFile("scrypt c2FsdA 18"), ClassSymmetric},
		{"ssh-rsa", ageFile("ssh-rsa AAAA dGVzdA"), ClassExposed},
		{"armored", []byte(pemBlock("AGE ENCRYPTED FILE", ageFile(pq))), ClassPQ},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := one(t, inspectBytes(t, "secret.age", tc.data))
			expect(t, f, tc.class)
		})
	}
	f := one(t, inspectBytes(t, "plugin.age", ageFile("yubikey-v9 dGVzdA")))
	if f.Class != ClassExposed || f.Confidence != "low" || f.Limits == "" {
		t.Errorf("unknown plugin: %+v", f)
	}
}

func TestJOSE(t *testing.T) {
	var log strings.Builder
	for i := 0; i < 3; i++ {
		log.WriteString("GET /api Authorization: Bearer " + jose(`{"alg":"RSA-OAEP-256","enc":"A256GCM"}`, 5) + "\n")
	}
	log.WriteString("token=" + jose(`{"alg":"HS256","typ":"JWT"}`, 3) + "\n")
	log.WriteString("id_token=" + jose(`{"alg":"RS256","kid":"k1"}`, 3) + "\n")
	log.WriteString("x=" + jose(`{"alg":"dir","enc":"A128GCM"}`, 5) + "\n")
	r := inspectBytes(t, "access.log", []byte(log.String()))
	byAlg := map[string]Finding{}
	for _, f := range r.Findings {
		byAlg[strings.Fields(f.Protection)[0]] = f
	}
	if f := byAlg["RSA-OAEP-256"]; f.Class != ClassExposed || f.Count != 3 {
		t.Errorf("JWE RSA-OAEP-256: %+v", f)
	}
	if f := byAlg["HS256"]; f.Class != ClassSymmetric {
		t.Errorf("HS256: %+v", f)
	}
	if f := byAlg["RS256"]; f.Class != ClassInventory {
		t.Errorf("RS256: %+v", f)
	}
	if f := byAlg["direct"]; f.Class != ClassSymmetric || !f.has(FlagAES128) {
		t.Errorf("dir/A128GCM: %+v", f)
	}
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e.Value, "eyJ") {
				t.Errorf("a token leaked into the evidence: %+v", e)
			}
		}
	}
}

func ecCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "svc.corp.local"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

func pemBlock(typ string, b []byte, headers ...string) string {
	blk := &pem.Block{Type: typ, Bytes: b, Headers: map[string]string{}}
	for i := 0; i+1 < len(headers); i += 2 {
		blk.Headers[headers[i]] = headers[i+1]
	}
	return string(pem.EncodeToMemory(blk))
}

func TestKeysAndCertificates(t *testing.T) {
	certDER, ecKey := ecCert(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mail.corp.local"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature}
	rsaCert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecP8, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xP8, _ := x509.MarshalPKCS8PrivateKey(x)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edP8, _ := x509.MarshalPKCS8PrivateKey(edKey)

	cases := []struct {
		name, file, text string
		class            Class
		flags            []string
		prot             string
	}{
		{"ec certificate", "ec.crt", pemBlock("CERTIFICATE", certDER), ClassInventory, []string{FlagClassicalKey}, "EC P-256"},
		{"rsa key-transport certificate", "mail.crt", pemBlock("CERTIFICATE", rsaCert), ClassInventory, []string{FlagClassicalEncKey}, "RSA 2048"},
		{"pkcs8 ec", "ec.key", pemBlock("PRIVATE KEY", ecP8), ClassInventory, []string{FlagPlainPrivateKey}, "EC P-256"},
		{"pkcs8 x25519", "x.key", pemBlock("PRIVATE KEY", xP8), ClassInventory, []string{FlagClassicalEncKey}, "X25519"},
		{"pkcs8 ed25519", "ed.key", pemBlock("PRIVATE KEY", edP8), ClassInventory, []string{FlagClassicalKey}, "Ed25519"},
		{"pkcs1 rsa", "rsa.key", pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), ClassInventory, []string{FlagPlainPrivateKey}, "RSA 2048"},
		{"legacy encrypted pem", "old.key", pemBlock("RSA PRIVATE KEY", []byte{1, 2, 3}, "Proc-Type", "4,ENCRYPTED", "DEK-Info", "DES-EDE3-CBC,0102030405060708"), ClassWeak, []string{FlagLegacyCipher}, "DES-EDE3-CBC"},
		{"encrypted pkcs8, pbes2 aes-256", "enc.key", pemBlock("ENCRYPTED PRIVATE KEY", seq(pbes2("2.16.840.1.101.3.4.1.42"), octets(make([]byte, 64)))), ClassInventory, nil, "AES-256-CBC"},
		{"encrypted pkcs8, legacy 3des", "enc3.key", pemBlock("ENCRYPTED PRIVATE KEY", seq(algID("1.2.840.113549.1.12.1.3", seq(octets(make([]byte, 8)), integer(2048))), octets(make([]byte, 64)))), ClassWeak, []string{FlagLegacyCipher}, "3DES"},
		{"ml-dsa public key", "pq.pub", pemBlock("PUBLIC KEY", seq(algID("2.16.840.1.101.3.4.3.18"), bitString(make([]byte, 1952)))), ClassPQ, nil, "ML-DSA-65"},
		{"ml-kem private key", "kem.key", pemBlock("PRIVATE KEY", seq(integer(0), algID("2.16.840.1.101.3.4.4.2"), octets(make([]byte, 64)))), ClassPQ, []string{FlagPlainPrivateKey}, "ML-KEM-768"},
		{"openssh unencrypted", "id_ed25519", pemBlock("OPENSSH PRIVATE KEY", opensshKey("none")), ClassInventory, []string{FlagPlainPrivateKey}, "Ed25519"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := one(t, inspectBytes(t, tc.file, []byte(tc.text)))
			expect(t, f, tc.class, tc.flags...)
			if !strings.Contains(f.Protection, tc.prot) {
				t.Errorf("protection %q, want %q", f.Protection, tc.prot)
			}
		})
	}

	f := one(t, inspectBytes(t, "id_ed25519", []byte(pemBlock("OPENSSH PRIVATE KEY", opensshKey("aes256-ctr")))))
	if f.has(FlagPlainPrivateKey) {
		t.Error("a passphrase-protected OpenSSH key was reported as unprotected")
	}

	// DER certificate, no PEM.
	expect(t, one(t, inspectBytes(t, "ec.der", certDER)), ClassInventory)

	// A key and a certificate in one PEM bundle are two findings.
	r := inspectBytes(t, "bundle.pem", []byte(pemBlock("CERTIFICATE", certDER)+pemBlock("PRIVATE KEY", ecP8)))
	if len(r.Findings) != 2 {
		t.Fatalf("bundle: %d findings", len(r.Findings))
	}
}

func TestSSHPublicKeys(t *testing.T) {
	ed := base64.StdEncoding.EncodeToString(sshEd25519Blob())
	rsa := base64.StdEncoding.EncodeToString(sshRSABlob(3072))
	text := "ssh-ed25519 " + ed + " alice@laptop\nssh-ed25519 " + ed + " bob@laptop\nfrom=\"10.0.0.0/8\" ssh-rsa " + rsa + " deploy\n"
	r := inspectBytes(t, "home/alice/.ssh/authorized_keys", []byte(text))
	if len(r.Findings) != 2 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Format != "SSH authorized keys" || f.Class != ClassInventory {
			t.Errorf("finding %+v", f)
		}
		if strings.Contains(f.Protection, "Ed25519") && f.Count != 2 || strings.Contains(f.Protection, "RSA") && (f.Count != 1 || f.Protection != "RSA 3072") {
			t.Errorf("counts: %+v", f)
		}
	}
}

func TestAgeKeysAndSOPS(t *testing.T) {
	x := "age1" + strings.Repeat("q", 58)
	pq := "age1pq1" + strings.Repeat("q", 60)
	r := inspectBytes(t, ".sops.yaml", []byte("creation_rules:\n  - age: "+x+","+pq+"\n"))
	if len(r.Findings) != 2 {
		t.Fatalf("recipients: %+v", r.Findings)
	}
	id := "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58)
	r = inspectBytes(t, "key.txt", []byte(id+"\n"))
	expect(t, one(t, r), ClassInventory, FlagClassicalEncKey, FlagPlainPrivateKey)

	var f Finding
	sops := `data: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]
sops:
    kms:
        - arn: arn:aws:kms:eu-west-1:111122223333:key/abcd
    age:
        - recipient: ` + x + `
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdl
            -----END AGE ENCRYPTED FILE-----
    version: 3.9.0
`
	f = one(t, inspectBytes(t, "secrets.yaml", []byte(sops)))
	expect(t, f, ClassExposed, FlagClassicalRecipient)
	kmsOnly := strings.Replace(sops, "    age:\n        - recipient: "+x+"\n", "    age: []\n", 1)
	kmsOnly = kmsOnly[:strings.Index(kmsOnly, "          enc:")] + "    version: 3.9.0\n"
	f = one(t, inspectBytes(t, "secrets.yaml", []byte(kmsOnly)))
	expect(t, f, ClassSymmetric)
}

func TestSymmetricContainers(t *testing.T) {
	luks1 := make([]byte, 592)
	copy(luks1, luksMagic)
	binary.BigEndian.PutUint16(luks1[6:], 1)
	copy(luks1[8:], "aes")
	copy(luks1[40:], "xts-plain64")
	copy(luks1[72:], "sha256")
	binary.BigEndian.PutUint32(luks1[108:], 64)
	f := one(t, inspectBytes(t, "disk.img", luks1))
	expect(t, f, ClassSymmetric)
	if !strings.Contains(f.Protection, "256-bit") {
		t.Errorf("LUKS1: %q", f.Protection)
	}

	meta := `{"keyslots":{"0":{"type":"luks2","key_size":32,"kdf":{"type":"argon2id"}}},"segments":{"0":{"type":"crypt","encryption":"aes-xts-plain64"}},"tokens":{"0":{"type":"systemd-tpm2"}}}`
	luks2 := make([]byte, 16384)
	copy(luks2, luksMagic)
	binary.BigEndian.PutUint16(luks2[6:], 2)
	binary.BigEndian.PutUint64(luks2[8:], 16384)
	copy(luks2[4096:], meta)
	f = one(t, inspectBytes(t, "disk2.img", luks2))
	expect(t, f, ClassSymmetric, FlagAES128)

	kdbx := []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x01, 0x00, 0x04, 0x00}
	field := func(id byte, v []byte) []byte {
		b := []byte{id, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b[1:], uint32(len(v)))
		return append(b, v...)
	}
	aes := []byte{0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff}
	argon := []byte{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6}
	vd := append([]byte{0, 1, 0x42, 5, 0, 0, 0}, "$UUID"...)
	vd = append(append(vd, 16, 0, 0, 0), argon...)
	kdbx = append(append(append(kdbx, field(2, aes)...), field(11, vd)...), field(0, nil)...)
	f = one(t, inspectBytes(t, "vault.kdbx", kdbx))
	expect(t, f, ClassSymmetric)
	if f.Evidence[0].Value != "AES-256" || f.Evidence[1].Value != "Argon2id" {
		t.Errorf("kdbx evidence %+v", f.Evidence)
	}

	f = one(t, inspectBytes(t, "backup.enc", append([]byte("Salted__12345678"), make([]byte, 32)...)))
	expect(t, f, ClassSymmetric, FlagUndeclaredCipher)

	f = one(t, inspectBytes(t, "vault.yml", []byte("$ANSIBLE_VAULT;1.1;AES256\n6231643964\n")))
	expect(t, f, ClassSymmetric)

	jks := []byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0, 0, 0, 1}
	certDER, _ := ecCert(t)
	jks = append(jks, 0, 0, 0, 2, 0, 2, 'c', 'a')
	jks = append(jks, make([]byte, 8)...)
	jks = append(jks, 0, 5, 'X', '.', '5', '0', '9')
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(certDER)))
	jks = append(append(jks, l...), certDER...)
	f = one(t, inspectBytes(t, "store.jks", jks))
	expect(t, f, ClassWeak, FlagLegacyCipher, FlagClassicalKey)
	if !strings.Contains(f.Evidence[len(f.Evidence)-1].Value, "EC P-256") {
		t.Errorf("JKS certificates: %+v", f.Evidence)
	}
}

func TestArchivesAndMail(t *testing.T) {
	certDER, ecKey := ecCert(t)
	ecP8, _ := x509.MarshalPKCS8PrivateKey(ecKey)

	// tar.gz holding a key, inside a zip that also holds an age file.
	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	key := []byte(pemBlock("PRIVATE KEY", ecP8))
	tw.WriteHeader(&tar.Header{Name: "etc/ssl/svc.key", Mode: 0600, Size: int64(len(key)), Typeflag: tar.TypeReg})
	tw.Write(key)
	tw.WriteHeader(&tar.Header{Name: "etc/ssl/link", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
	tw.Close()
	gz.Close()

	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	w, _ := zw.Create("backup/data.age")
	w.Write(ageFile("X25519 dGVzdA"))
	w, _ = zw.Create("backup/certs.tar.gz")
	w.Write(tgz.Bytes())
	// An encrypted entry: flag bit 0, stored raw, ZipCrypto.
	w, _ = zw.CreateRaw(&zip.FileHeader{Name: "backup/secret.txt", Method: zip.Store, Flags: 1, CompressedSize64: 12, UncompressedSize64: 0})
	w.Write(make([]byte, 12))
	zw.Close()

	r := inspectBytes(t, "backup.zip", z.Bytes())
	got := map[string]Class{}
	for _, f := range r.Findings {
		got[f.Path] = f.Class
	}
	want := map[string]Class{
		"backup.zip!backup/data.age":                     ClassExposed,
		"backup.zip!backup/certs.tar.gz!etc/ssl/svc.key": ClassInventory,
		"backup.zip": ClassWeak, // ZipCrypto entry
	}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("%s: class %q, want %q (all: %v)", p, got[p], c, got)
		}
	}
	linkSkipped := false
	for _, s := range r.Skipped {
		linkSkipped = linkSkipped || strings.HasSuffix(s.Path, "etc/ssl/link")
	}
	if !linkSkipped {
		t.Errorf("tar symlink should be skipped, not followed: %+v", r.Skipped)
	}

	// S/MIME mail with an encrypted attachment, and an mbox with a PGP message.
	p7m := base64.StdEncoding.EncodeToString(envelopedData("2.16.840.1.101.3.4.1.42", ktri("1.2.840.113549.1.1.1")))
	eml := "From: a@example.com\r\nTo: b@example.com\r\nSubject: Q3 numbers\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--XYZ\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n" +
		"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\n" + wrap(p7m) + "\r\n--XYZ--\r\n"
	f := one(t, inspectBytes(t, "q3.eml", []byte(eml)))
	expect(t, f, ClassExposed)
	if f.Path != "q3.eml/part 2 (smime.p7m)" {
		t.Errorf("mail path %q", f.Path)
	}
	for _, e := range f.Evidence {
		if strings.Contains(e.Value, "Q3") || strings.Contains(e.Value, "example.com") {
			t.Errorf("mail headers leaked: %+v", e)
		}
	}

	mbox := "From alice Mon Jan  1 00:00:00 2026\nFrom: a@x\nContent-Type: text/plain\n\nhello\n\n" +
		"From bob Mon Jan  1 00:00:00 2026\nFrom: b@x\nContent-Type: text/plain\n\n" + armorPGP("PGP MESSAGE", cat(pkeskV6(35), seipdV2(9)))
	f = one(t, inspectBytes(t, "INBOX", []byte(mbox)))
	expect(t, f, ClassPQ)
	if !strings.HasPrefix(f.Path, "INBOX#message 2/part 1") {
		t.Errorf("mbox path %q", f.Path)
	}
	_ = certDER
}

func wrap(s string) string {
	var out []string
	for len(s) > 76 {
		out = append(out, s[:76])
		s = s[76:]
	}
	return strings.Join(append(out, s), "\r\n")
}

func TestWalkerLimits(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.age"), ageFile("X25519 dGVzdA"), 0600)
	os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	// A large file: only its head is read, and the header there still classifies it.
	big := append(envelopedData("2.16.840.1.101.3.4.1.42", ktri("1.2.840.113549.1.1.1")), make([]byte, 3<<20)...)
	os.WriteFile(filepath.Join(dir, "big.p7m"), big, 0600)

	in := New(context.Background(), Options{MaxFileSize: 1 << 20}, nil)
	in.Path(dir)
	r := in.Report()
	if r.Counts[ClassExposed] != 2 {
		t.Fatalf("findings: %+v skipped: %+v", r.Findings, r.Skipped)
	}
	reasons := map[string]string{}
	for _, s := range r.Skipped {
		reasons[filepath.Base(s.Path)] = s.Reason
	}
	if !strings.Contains(reasons["link"], "symbolic link") || !strings.Contains(reasons["big.p7m"], "first 1 MiB") {
		t.Errorf("skips: %+v", reasons)
	}

	// A zip bomb stops at the per-file limit.
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	w, _ := zw.Create("bomb.txt")
	w.Write(make([]byte, 4<<20))
	zw.Close()
	in = New(context.Background(), Options{MaxFileSize: 1 << 20}, nil)
	in.Bytes("bomb.zip", z.Bytes())
	if r := in.Report(); r.SkippedTotal != 1 || !strings.Contains(r.Skipped[0].Reason, "per-file limit") {
		t.Errorf("zip bomb: %+v", r.Skipped)
	}

	// Plain files produce nothing and an Undetermined verdict.
	r = inspectBytes(t, "readme.md", []byte("# hello\nnothing to see\n"))
	if len(r.Findings) != 0 || r.Verdict != "undetermined" {
		t.Errorf("plain: %+v", r)
	}
}

func TestReportAndRecommendations(t *testing.T) {
	in := New(context.Background(), Options{}, nil)
	in.Bytes("a.age", ageFile("X25519 dGVzdA"))
	in.Bytes("b.age", ageFile("mlkem768x25519 dGVzdA"))
	in.Bytes("old.zip", func() []byte {
		var z bytes.Buffer
		zw := zip.NewWriter(&z)
		w, _ := zw.CreateRaw(&zip.FileHeader{Name: "x", Method: zip.Store, Flags: 1, CompressedSize64: 12})
		w.Write(make([]byte, 12))
		zw.Close()
		return z.Bytes()
	}())
	r := in.Report()
	if r.Verdict != "not_ready" || r.Findings[0].Class != ClassExposed {
		t.Fatalf("report: %+v", r)
	}
	if r.Headline != "1 of 3 artifacts is encrypted to a classical public key: exposed to harvest-now-decrypt-later; 1 uses weak protection." {
		t.Errorf("headline %q", r.Headline)
	}
	ids := map[string][]string{}
	for _, rec := range r.Recommendations {
		ids[rec.ID] = rec.Services
	}
	if len(ids["reencrypt-pq"]) != 1 || ids["reencrypt-pq"][0] != "a.age" || len(ids["replace-weak"]) != 1 {
		t.Errorf("recommendations: %v", ids)
	}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
