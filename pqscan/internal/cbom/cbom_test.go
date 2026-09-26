package cbom

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"pqscan/internal/inspect"
	"pqscan/internal/observe"
	"pqscan/internal/probe"
	"pqscan/internal/report"
)

// Enumerations from the CycloneDX 1.6 JSON schema (bom-1.6.schema.json,
// definitions/cryptoProperties).
var (
	enumAsset     = set("algorithm", "certificate", "protocol", "related-crypto-material")
	enumPrimitive = set("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown")
	enumMode      = set("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown")
	enumPadding   = set("pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown")
	enumFunctions = set("generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown")
	enumMaterial  = set("private-key", "public-key", "secret-key", "key", "ciphertext", "signature", "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret", "tag", "additional-data", "password", "credential", "token", "other", "unknown")
	enumProtocol  = set("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown")
	serialRE      = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}

// check enforces the schema constraints pqscan's output touches, plus
// referential integrity: every ref points at a component in the document.
func check(t *testing.T, doc BOM) map[string]Component {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back BOM
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" || !serialRE.MatchString(doc.SerialNumber) || doc.Version != 1 {
		t.Fatalf("header: %+v", doc)
	}
	if _, err := time.Parse(time.RFC3339, doc.Metadata.Timestamp); err != nil {
		t.Errorf("timestamp: %v", err)
	}
	byRef := map[string]Component{}
	for _, c := range doc.Components {
		if c.Type != "cryptographic-asset" || c.Name == "" || c.BOMRef == "" {
			t.Errorf("component: %+v", c)
		}
		if _, dup := byRef[c.BOMRef]; dup {
			t.Errorf("duplicate bom-ref %s", c.BOMRef)
		}
		byRef[c.BOMRef] = c
		if c.Evidence != nil {
			for _, o := range c.Evidence.Occurrences {
				if o.Location == "" {
					t.Errorf("%s: occurrence without location", c.BOMRef)
				}
			}
		}
	}
	refOK := func(owner, ref string) {
		if ref != "" && byRef[ref].BOMRef == "" {
			t.Errorf("%s refers to missing %s", owner, ref)
		}
	}
	for _, c := range doc.Components {
		cp := c.CryptoProperties
		if cp == nil || !enumAsset[cp.AssetType] {
			t.Fatalf("%s: cryptoProperties %+v", c.BOMRef, cp)
		}
		if a := cp.AlgorithmProperties; a != nil {
			if !enumPrimitive[a.Primitive] || a.Mode != "" && !enumMode[a.Mode] || a.Padding != "" && !enumPadding[a.Padding] {
				t.Errorf("%s: algorithm %+v", c.BOMRef, a)
			}
			for _, f := range a.CryptoFunctions {
				if !enumFunctions[f] {
					t.Errorf("%s: function %q", c.BOMRef, f)
				}
			}
			if q := a.NISTQuantumSecurityLevel; q != nil && (*q < 0 || *q > 6) {
				t.Errorf("%s: quantum level %d", c.BOMRef, *q)
			}
		}
		if p := cp.CertificateProperties; p != nil {
			refOK(c.BOMRef, p.SignatureAlgorithmRef)
			refOK(c.BOMRef, p.SubjectPublicKeyRef)
			if p.NotValidAfter != "" {
				if _, err := time.Parse(time.RFC3339, p.NotValidAfter); err != nil {
					t.Errorf("%s: notValidAfter %q", c.BOMRef, p.NotValidAfter)
				}
			}
		}
		if m := cp.RelatedCryptoMaterialProperties; m != nil {
			if !enumMaterial[m.Type] {
				t.Errorf("%s: material type %q", c.BOMRef, m.Type)
			}
			refOK(c.BOMRef, m.AlgorithmRef)
			if m.SecuredBy != nil {
				refOK(c.BOMRef, m.SecuredBy.AlgorithmRef)
			}
		}
		if p := cp.ProtocolProperties; p != nil {
			if !enumProtocol[p.Type] {
				t.Errorf("%s: protocol %q", c.BOMRef, p.Type)
			}
			for _, r := range p.CryptoRefArray {
				refOK(c.BOMRef, r)
			}
			for _, s := range p.CipherSuites {
				for _, r := range s.Algorithms {
					refOK(c.BOMRef, r)
				}
			}
		}
	}
	return byRef
}

func level(c Component) int {
	if c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties == nil {
		return -2 // missing
	}
	if q := c.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel; q != nil {
		return *q
	}
	return -1
}

func TestHostAndEstate(t *testing.T) {
	pq := report.ForService(probe.ServiceResult{Service: "HTTPS", Kind: "tls", Host: "mail.corp.local", Port: 443, Reachable: true,
		TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_256_GCM_SHA384", NegotiatedGroup: "X25519MLKEM768", PQKeyExchange: true, BestPQGroup: "X25519MLKEM768",
		Groups:     []probe.GroupResult{{Group: "X25519MLKEM768", Supported: true}, {Group: "SecP256r1MLKEM768", Supported: true}},
		CertSigAlg: "SHA256-RSA", CertSubject: "mail.corp.local", CertNotAfter: "2027-01-02T03:04:05Z"}, report.Env{})
	ssh := report.ForService(probe.ServiceResult{Service: "SSH", Kind: "ssh", Host: "mail.corp.local", Port: 22, Reachable: true,
		Banner: "SSH-2.0-OpenSSH_9.6", Advertised: []string{"curve25519-sha256", "sntrup761x25519-sha512@openssh.com"}}, report.Env{})
	hr := report.Rollup("mail.corp.local", []report.ServiceReport{pq, ssh}, 2, false, report.Env{})
	b := NewBuilder()
	b.AddEstate(report.Estate([]report.HostReport{hr}, 1, report.Env{}))
	refs := check(t, b.BOM())
	for ref, want := range map[string]int{"crypto/algorithm/x25519mlkem768": 3, "crypto/algorithm/secp256r1mlkem768": 3, "crypto/algorithm/aes256gcm": 5, "crypto/algorithm/sha256rsa": 0, "crypto/algorithm/curve25519sha256": 0} {
		c, ok := refs[ref]
		if !ok {
			t.Errorf("missing %s (have %v)", ref, keys(refs))
			continue
		}
		if got := level(c); got != want {
			t.Errorf("%s: quantum level %d, want %d", ref, got, want)
		}
	}
	tls := refs["crypto/protocol/tls/mail.corp.local:443"]
	if p := tls.CryptoProperties.ProtocolProperties; p == nil || p.Version != "1.3" || len(p.CipherSuites) != 1 {
		t.Errorf("TLS protocol asset: %+v", tls)
	}
	if c := refs["crypto/certificate/mail.corp.local:443"]; c.CryptoProperties.CertificateProperties.NotValidAfter != "2027-01-02T03:04:05Z" {
		t.Errorf("certificate: %+v", c.CryptoProperties)
	}
}

func keys(m map[string]Component) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInspectAndObserve(t *testing.T) {
	in := inspect.New(context.Background(), inspect.Options{}, nil)
	in.Bytes("backup/a.age", []byte("age-encryption.org/v1\n-> X25519 dGVzdA\nYm9keQ\n--- bWFj\n\x00"))
	in.Bytes("backup/b.age", []byte("age-encryption.org/v1\n-> mlkem768x25519 dGVzdA\nYm9keQ\n--- bWFj\n\x00"))
	in.Bytes("vault.yml", []byte("$ANSIBLE_VAULT;1.1;AES256\n6231\n"))
	b := NewBuilder()
	b.AddInspect(in.Report())
	refs := check(t, b.BOM())
	var ciphertexts int
	for _, c := range refs {
		if m := c.CryptoProperties.RelatedCryptoMaterialProperties; m != nil && m.Type == "ciphertext" {
			ciphertexts++
			if strings.HasSuffix(c.Name, "a.age") && (m.SecuredBy == nil || m.SecuredBy.AlgorithmRef != "crypto/algorithm/x25519") {
				t.Errorf("a.age should be secured by X25519: %+v", m)
			}
		}
	}
	if ciphertexts != 3 || level(refs["crypto/algorithm/x25519"]) != 0 || level(refs["crypto/algorithm/mlkem768+x25519"]) != 3 {
		t.Errorf("ciphertexts %d, refs %v", ciphertexts, keys(refs))
	}

	o := observe.Report{Groups: []observe.Connection{
		{Protocol: "TLS", ClientIP: "10.0.0.5", Server: "10.0.0.9:443", ServerName: "svc", Class: observe.ClassClassical, Outcome: "client-classical",
			KeyExchange: "X25519", Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Count: 3,
			Evidence: []inspect.Fact{{Label: "Server signature", Value: "mldsa65"}}},
		{Protocol: "IKEv2", ClientIP: "10.0.0.5", Server: "10.0.0.1:500", Class: observe.ClassPQ, Outcome: "pq", KeyExchange: "Curve25519 + ML-KEM-768", Count: 1},
		{Protocol: "HTTP", ClientIP: "10.0.0.5", Server: "10.0.0.9:80", Class: observe.ClassPlaintext, Outcome: "plaintext", KeyExchange: "none (plaintext)", Count: 1},
	}}
	b = NewBuilder()
	b.AddObserve(o)
	refs = check(t, b.BOM())
	ike := refs["crypto/protocol/ikev2/10.0.0.5/10.0.0.1:500"]
	if _, ok := refs["crypto/protocol/tls/10.0.0.5/10.0.0.9:443/svc"]; !ok {
		t.Errorf("TLS asset ref: %v", keys(refs))
	}
	if ike.CryptoProperties == nil || ike.CryptoProperties.ProtocolProperties.IKEv2TransformTypes == nil || len(ike.CryptoProperties.ProtocolProperties.IKEv2TransformTypes.KE) != 2 {
		t.Errorf("IKE asset: %v", keys(refs))
	}
	if level(refs["crypto/algorithm/mldsa65"]) != 3 || level(refs["crypto/algorithm/mlkem768"]) != 3 {
		t.Errorf("post-quantum levels: %v", keys(refs))
	}
	for ref := range refs {
		if strings.Contains(ref, "http") {
			t.Errorf("plaintext connections have no cryptography to list: %s", ref)
		}
	}
}
