package cbom

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// spec describes an algorithm in CycloneDX terms.
type spec struct {
	name      string // canonical display name
	primitive string // CycloneDX primitive
	param     string // parameterSetIdentifier
	curve     string
	mode      string
	padding   string
	functions []string
	classical int // classical security level in bits (0 = not stated)
	quantum   int // NIST quantum security category; -1 = not stated
	oid       string
}

var (
	kemFns    = []string{"keygen", "encapsulate", "decapsulate"}
	agreeFns  = []string{"keygen", "keyderive"}
	sigFns    = []string{"sign", "verify"}
	cipherFns = []string{"encrypt", "decrypt"}
	pkeFns    = []string{"encrypt", "decrypt"}
)

// known maps lower-cased names (from every pqscan mode) to specs. Quantum
// categories follow NIST's PQC definitions: 1/3/5 for the ML-KEM, ML-DSA, and
// SLH-DSA parameter sets and for AES-128/192/256; 0 for anything Shor's
// algorithm breaks; SHA-256 and SHA-384 are categories 2 and 4.
var known = map[string]spec{
	"x25519mlkem768":              {name: "X25519MLKEM768", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"secp256r1mlkem768":           {name: "SecP256r1MLKEM768", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"secp384r1mlkem1024":          {name: "SecP384r1MLKEM1024", primitive: "kem", param: "1024", functions: kemFns, quantum: 5},
	"x25519kyber768draft00":       {name: "X25519Kyber768Draft00", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"mlkem512":                    {name: "ML-KEM-512", primitive: "kem", param: "512", functions: kemFns, quantum: 1, oid: "2.16.840.1.101.3.4.4.1"},
	"mlkem768":                    {name: "ML-KEM-768", primitive: "kem", param: "768", functions: kemFns, quantum: 3, oid: "2.16.840.1.101.3.4.4.2"},
	"mlkem1024":                   {name: "ML-KEM-1024", primitive: "kem", param: "1024", functions: kemFns, quantum: 5, oid: "2.16.840.1.101.3.4.4.3"},
	"mlkem768x25519sha256":        {name: "mlkem768x25519-sha256", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"sntrup761x25519sha512":       {name: "sntrup761x25519-sha512", primitive: "kem", param: "761", functions: kemFns, quantum: -1},
	"mlkem768+x25519":             {name: "ML-KEM-768+X25519", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"mlkem1024+x448":              {name: "ML-KEM-1024+X448", primitive: "kem", param: "1024", functions: kemFns, quantum: 5},
	"mlkem768x25519":              {name: "ML-KEM-768 + X25519", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"mlkem768+p256hardwaretag":    {name: "ML-KEM-768 + P-256", primitive: "kem", param: "768", functions: kemFns, quantum: 3},
	"mldsa44":                     {name: "ML-DSA-44", primitive: "signature", param: "44", functions: sigFns, quantum: 2, oid: "2.16.840.1.101.3.4.3.17"},
	"mldsa65":                     {name: "ML-DSA-65", primitive: "signature", param: "65", functions: sigFns, quantum: 3, oid: "2.16.840.1.101.3.4.3.18"},
	"mldsa87":                     {name: "ML-DSA-87", primitive: "signature", param: "87", functions: sigFns, quantum: 5, oid: "2.16.840.1.101.3.4.3.19"},
	"mldsa65+ed25519":             {name: "ML-DSA-65+Ed25519", primitive: "signature", param: "65", functions: sigFns, quantum: 3},
	"mldsa87+ed448":               {name: "ML-DSA-87+Ed448", primitive: "signature", param: "87", functions: sigFns, quantum: 5},
	"x25519":                      {name: "X25519", primitive: "key-agree", curve: "Curve25519", functions: agreeFns, classical: 128, quantum: 0, oid: "1.3.101.110"},
	"curve25519":                  {name: "X25519", primitive: "key-agree", curve: "Curve25519", functions: agreeFns, classical: 128, quantum: 0, oid: "1.3.101.110"},
	"x448":                        {name: "X448", primitive: "key-agree", curve: "Curve448", functions: agreeFns, classical: 224, quantum: 0, oid: "1.3.101.111"},
	"curve448":                    {name: "X448", primitive: "key-agree", curve: "Curve448", functions: agreeFns, classical: 224, quantum: 0, oid: "1.3.101.111"},
	"secp256r1":                   {name: "ECDH-P-256", primitive: "key-agree", curve: "secp256r1", functions: agreeFns, classical: 128, quantum: 0},
	"secp384r1":                   {name: "ECDH-P-384", primitive: "key-agree", curve: "secp384r1", functions: agreeFns, classical: 192, quantum: 0},
	"secp521r1":                   {name: "ECDH-P-521", primitive: "key-agree", curve: "secp521r1", functions: agreeFns, classical: 256, quantum: 0},
	"ecp256":                      {name: "ECDH-P-256", primitive: "key-agree", curve: "secp256r1", functions: agreeFns, classical: 128, quantum: 0},
	"ecp384":                      {name: "ECDH-P-384", primitive: "key-agree", curve: "secp384r1", functions: agreeFns, classical: 192, quantum: 0},
	"ecp521":                      {name: "ECDH-P-521", primitive: "key-agree", curve: "secp521r1", functions: agreeFns, classical: 256, quantum: 0},
	"curve25519sha256":            {name: "curve25519-sha256", primitive: "key-agree", curve: "Curve25519", functions: agreeFns, classical: 128, quantum: 0},
	"curve25519sha256@libssh.org": {name: "curve25519-sha256", primitive: "key-agree", curve: "Curve25519", functions: agreeFns, classical: 128, quantum: 0},
	"ecdhsha2nistp256":            {name: "ecdh-sha2-nistp256", primitive: "key-agree", curve: "secp256r1", functions: agreeFns, classical: 128, quantum: 0},
	"ecdhsha2nistp384":            {name: "ecdh-sha2-nistp384", primitive: "key-agree", curve: "secp384r1", functions: agreeFns, classical: 192, quantum: 0},
	"ecdhsha2nistp521":            {name: "ecdh-sha2-nistp521", primitive: "key-agree", curve: "secp521r1", functions: agreeFns, classical: 256, quantum: 0},
	"rsakeytransport":             {name: "RSA key transport", primitive: "pke", padding: "pkcs1v15", functions: pkeFns, quantum: 0},
	"aes128gcm":                   {name: "AES-128-GCM", primitive: "ae", param: "128", mode: "gcm", functions: cipherFns, classical: 128, quantum: 1, oid: "2.16.840.1.101.3.4.1.6"},
	"aes256gcm":                   {name: "AES-256-GCM", primitive: "ae", param: "256", mode: "gcm", functions: cipherFns, classical: 256, quantum: 5, oid: "2.16.840.1.101.3.4.1.46"},
	"aes128cbc":                   {name: "AES-128-CBC", primitive: "block-cipher", param: "128", mode: "cbc", functions: cipherFns, classical: 128, quantum: 1, oid: "2.16.840.1.101.3.4.1.2"},
	"aes192cbc":                   {name: "AES-192-CBC", primitive: "block-cipher", param: "192", mode: "cbc", functions: cipherFns, classical: 192, quantum: 3, oid: "2.16.840.1.101.3.4.1.22"},
	"aes256cbc":                   {name: "AES-256-CBC", primitive: "block-cipher", param: "256", mode: "cbc", functions: cipherFns, classical: 256, quantum: 5, oid: "2.16.840.1.101.3.4.1.42"},
	"aes128":                      {name: "AES-128", primitive: "block-cipher", param: "128", functions: cipherFns, classical: 128, quantum: 1},
	"aes192":                      {name: "AES-192", primitive: "block-cipher", param: "192", functions: cipherFns, classical: 192, quantum: 3},
	"aes256":                      {name: "AES-256", primitive: "block-cipher", param: "256", functions: cipherFns, classical: 256, quantum: 5},
	"aes256ctr":                   {name: "AES-256-CTR", primitive: "block-cipher", param: "256", mode: "ctr", functions: cipherFns, classical: 256, quantum: 5},
	"chacha20poly1305":            {name: "ChaCha20-Poly1305", primitive: "ae", param: "256", functions: cipherFns, classical: 256, quantum: 5},
	"3descbc":                     {name: "3DES-CBC", primitive: "block-cipher", param: "168", mode: "cbc", functions: cipherFns, classical: 112, quantum: 0},
	"tripledes":                   {name: "3DES", primitive: "block-cipher", param: "168", functions: cipherFns, classical: 112, quantum: 0},
	"sha256":                      {name: "SHA-256", primitive: "hash", param: "256", functions: []string{"digest"}, classical: 128, quantum: 2},
	"sha384":                      {name: "SHA-384", primitive: "hash", param: "384", functions: []string{"digest"}, classical: 192, quantum: 4},
	"sha512":                      {name: "SHA-512", primitive: "hash", param: "512", functions: []string{"digest"}, classical: 256, quantum: 5},
	"ed25519":                     {name: "Ed25519", primitive: "signature", curve: "Curve25519", functions: sigFns, classical: 128, quantum: 0, oid: "1.3.101.112"},
	"ed448":                       {name: "Ed448", primitive: "signature", curve: "Curve448", functions: sigFns, classical: 224, quantum: 0, oid: "1.3.101.113"},
	"sha256rsa":                   {name: "SHA256-RSA", primitive: "signature", padding: "pkcs1v15", functions: sigFns, quantum: 0, oid: "1.2.840.113549.1.1.11"},
	"sha384rsa":                   {name: "SHA384-RSA", primitive: "signature", padding: "pkcs1v15", functions: sigFns, quantum: 0, oid: "1.2.840.113549.1.1.12"},
	"sha512rsa":                   {name: "SHA512-RSA", primitive: "signature", padding: "pkcs1v15", functions: sigFns, quantum: 0, oid: "1.2.840.113549.1.1.13"},
	"ecdsasha256":                 {name: "ECDSA-SHA256", primitive: "signature", functions: sigFns, quantum: 0, oid: "1.2.840.10045.4.3.2"},
	"ecdsasha384":                 {name: "ECDSA-SHA384", primitive: "signature", functions: sigFns, quantum: 0, oid: "1.2.840.10045.4.3.3"},
	"ecdsasecp256r1sha256":        {name: "ECDSA-P-256-SHA256", primitive: "signature", curve: "secp256r1", functions: sigFns, classical: 128, quantum: 0},
	"ecdsasecp384r1sha384":        {name: "ECDSA-P-384-SHA384", primitive: "signature", curve: "secp384r1", functions: sigFns, classical: 192, quantum: 0},
	"rsapssrsaesha256":            {name: "RSASSA-PSS-SHA256", primitive: "signature", functions: sigFns, quantum: 0},
	"rsapssrsaesha384":            {name: "RSASSA-PSS-SHA384", primitive: "signature", functions: sigFns, quantum: 0},
	"rsapkcs1sha256":              {name: "RSASSA-PKCS1-v1_5-SHA256", primitive: "signature", padding: "pkcs1v15", functions: sigFns, quantum: 0},
	// JOSE (RFC 7518) names, unified with the algorithms they denote.
	"a128gcm":       {name: "AES-128-GCM", primitive: "ae", param: "128", mode: "gcm", functions: cipherFns, classical: 128, quantum: 1, oid: "2.16.840.1.101.3.4.1.6"},
	"a192gcm":       {name: "AES-192-GCM", primitive: "ae", param: "192", mode: "gcm", functions: cipherFns, classical: 192, quantum: 3, oid: "2.16.840.1.101.3.4.1.26"},
	"a256gcm":       {name: "AES-256-GCM", primitive: "ae", param: "256", mode: "gcm", functions: cipherFns, classical: 256, quantum: 5, oid: "2.16.840.1.101.3.4.1.46"},
	"a128kw":        {name: "AES-128 key wrap", primitive: "block-cipher", param: "128", mode: "other", functions: cipherFns, classical: 128, quantum: 1, oid: "2.16.840.1.101.3.4.1.5"},
	"a256kw":        {name: "AES-256 key wrap", primitive: "block-cipher", param: "256", mode: "other", functions: cipherFns, classical: 256, quantum: 5, oid: "2.16.840.1.101.3.4.1.45"},
	"aes128keywrap": {name: "AES-128 key wrap", primitive: "block-cipher", param: "128", mode: "other", functions: cipherFns, classical: 128, quantum: 1, oid: "2.16.840.1.101.3.4.1.5"},
	"aes256keywrap": {name: "AES-256 key wrap", primitive: "block-cipher", param: "256", mode: "other", functions: cipherFns, classical: 256, quantum: 5, oid: "2.16.840.1.101.3.4.1.45"},
	"rsaoaep":       {name: "RSA-OAEP", primitive: "pke", padding: "oaep", functions: pkeFns, quantum: 0, oid: "1.2.840.113549.1.1.7"},
	"rsaoaep256":    {name: "RSA-OAEP-256", primitive: "pke", padding: "oaep", functions: pkeFns, quantum: 0},
	"rsaesoaep":     {name: "RSA-OAEP", primitive: "pke", padding: "oaep", functions: pkeFns, quantum: 0, oid: "1.2.840.113549.1.1.7"},
	"es256ecdsa":    {name: "ECDSA-P-256-SHA256", primitive: "signature", curve: "secp256r1", functions: sigFns, classical: 128, quantum: 0},
	"es384ecdsa":    {name: "ECDSA-P-384-SHA384", primitive: "signature", curve: "secp384r1", functions: sigFns, classical: 192, quantum: 0},
	"rs256rsa":      {name: "RSASSA-PKCS1-v1_5-SHA256", primitive: "signature", padding: "pkcs1v15", functions: sigFns, quantum: 0},
	"ps256rsa":      {name: "RSASSA-PSS-SHA256", primitive: "signature", functions: sigFns, quantum: 0},
	"hs256hmac":     {name: "HMAC-SHA256", primitive: "mac", functions: []string{"tag"}, classical: 256, quantum: -1},
	"eddsa":         {name: "EdDSA", primitive: "signature", functions: sigFns, quantum: 0},
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9+@.]`)

func normalize(name string) string {
	n := strings.ToLower(name)
	for _, suffix := range []string{" (ecdhe)", " (noise ikpsk2)", " (static rsa)", " (sha-1 kdf)", " (sha-256 kdf)", " (sha-384 kdf)"} {
		n = strings.TrimSuffix(n, suffix)
	}
	n = strings.ReplaceAll(n, " + ", "+")
	return nonAlnum.ReplaceAllString(n, "")
}

// lookupSpec describes an algorithm name from any pqscan mode, falling back to
// hints: the primitive pqscan recorded, whether it resists quantum attacks, and bits.
func lookupSpec(name, primitiveHint string, pq bool, bits int) spec {
	if low := strings.ToLower(name); strings.HasPrefix(low, "ec ") { // an EC key, named by its curve
		c := ecCurves[strings.TrimPrefix(low, "ec ")]
		return spec{name: "EC-" + name[3:], primitive: "signature", curve: c.curve, functions: sigFns, classical: c.classical, quantum: 0}
	}
	if s, ok := known[normalize(name)]; ok {
		return s
	}
	s := spec{name: name, primitive: primitive(name, primitiveHint), quantum: -1}
	low := strings.ToLower(name)
	switch {
	case pq && (bits == 128 || bits == 192 || bits == 256):
		s.quantum = map[int]int{128: 1, 192: 3, 256: 5}[bits]
	case low == "ec":
		s.primitive, s.quantum = "signature", 0
	case !pq && (strings.Contains(low, "rsa") || strings.Contains(low, "ecdh") || strings.Contains(low, "ecdsa") || strings.Contains(low, "dsa") ||
		strings.Contains(low, "elgamal") || strings.Contains(low, "x25519") || strings.Contains(low, "diffie") || strings.Contains(low, "modp") ||
		strings.HasPrefix(low, "ec ") || strings.Contains(low, "p-256") || strings.Contains(low, "ed25519")):
		s.quantum = 0
	}
	if bits > 0 {
		s.param = strconv.Itoa(bits)
		if low == "rsa" || low == "dsa" || low == "elgamal" {
			s.name = fmt.Sprintf("%s-%d", name, bits)
			s.classical = map[int]int{1024: 80, 2048: 112, 3072: 128, 4096: 128, 7680: 192, 15360: 256}[bits]
		}
	}
	switch s.primitive {
	case "kem":
		s.functions = kemFns
	case "key-agree":
		s.functions = agreeFns
	case "signature":
		s.functions = sigFns
	case "ae", "block-cipher", "stream-cipher", "pke":
		s.functions = cipherFns
	case "kdf":
		s.functions = []string{"keyderive"}
	}
	return s
}

// ecCurves names EC keys by curve.
var ecCurves = map[string]struct {
	curve     string
	classical int
}{
	"p-256": {"secp256r1", 128}, "p-384": {"secp384r1", 192}, "p-521": {"secp521r1", 256},
	"secp256k1": {"secp256k1", 128}, "brainpoolp256r1": {"brainpoolP256r1", 128}, "brainpoolp384r1": {"brainpoolP384r1", 192},
}

// primitive maps pqscan's primitive names (and algorithm names) to CycloneDX's.
func primitive(name, hint string) string {
	low := strings.ToLower(name)
	switch hint {
	case "kem", "key-agree", "signature", "kdf", "mac", "hash":
		return hint
	case "key-transport":
		return "pke"
	case "pbe":
		return "kdf"
	case "cipher":
		switch {
		case strings.Contains(low, "gcm"), strings.Contains(low, "ccm"), strings.Contains(low, "poly1305"), strings.Contains(low, "ocb"):
			return "ae"
		case strings.Contains(low, "rc4"), strings.Contains(low, "chacha"):
			return "stream-cipher"
		}
		return "block-cipher"
	case "public-key":
		if strings.Contains(low, "rsa") {
			return "pke"
		}
		return "signature"
	}
	return "unknown"
}

// suiteAlgorithms splits a TLS cipher suite name into its algorithms.
// TLS 1.3 suites name the AEAD and the hash; TLS 1.2 suites also name the key
// exchange and authentication, which are reported separately.
func suiteAlgorithms(suite string) []string {
	s := strings.TrimPrefix(suite, "TLS_")
	if i := strings.Index(s, "_WITH_"); i >= 0 {
		s = s[i+6:]
	}
	parts := strings.Split(s, "_")
	if len(parts) < 2 {
		return nil
	}
	hash := parts[len(parts)-1]
	cipher := strings.Join(parts[:len(parts)-1], "-")
	cipher = strings.Replace(cipher, "CHACHA20-POLY1305", "ChaCha20-Poly1305", 1)
	var out []string
	if cipher != "" {
		out = append(out, cipher)
	}
	if strings.HasPrefix(hash, "SHA") {
		out = append(out, "SHA-"+strings.TrimPrefix(hash, "SHA"))
	}
	return out
}
