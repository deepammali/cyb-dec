package inspect

import "fmt"

// alg describes an algorithm identifier as it bears on quantum exposure.
type alg struct {
	name      string
	primitive string // kem, key-agree, key-transport, signature, cipher, kdf, pbe, public-key
	pq        bool   // not broken by a quantum attacker (ML-KEM, ML-DSA, SLH-DSA, AES)
	bits      int    // symmetric key size, for ciphers
	legacy    bool   // broken or deprecated today
}

// oids maps dotted OIDs to algorithms. Sources: RFC 5280/3279/5480/8410
// (public keys), NIST CSOR (AES, ML-KEM 2.16.840.1.101.3.4.4.*, ML-DSA and
// SLH-DSA 2.16.840.1.101.3.4.3.*), RFC 5652/8018/7292 (CMS, PKCS#5, PKCS#12),
// RFC 9629 (KEMRecipientInfo).
var oids = map[string]alg{
	// public keys
	"1.2.840.113549.1.1.1":  {name: "RSA", primitive: "public-key"},
	"1.2.840.113549.1.1.7":  {name: "RSAES-OAEP", primitive: "key-transport"},
	"1.2.840.113549.1.1.10": {name: "RSASSA-PSS", primitive: "signature"},
	"1.2.840.10045.2.1":     {name: "EC", primitive: "public-key"},
	"1.3.101.110":           {name: "X25519", primitive: "key-agree"},
	"1.3.101.111":           {name: "X448", primitive: "key-agree"},
	"1.3.101.112":           {name: "Ed25519", primitive: "signature"},
	"1.3.101.113":           {name: "Ed448", primitive: "signature"},
	"1.2.840.10040.4.1":     {name: "DSA", primitive: "signature"},
	"1.2.840.113549.1.3.1":  {name: "DH", primitive: "key-agree"},
	"1.2.840.10046.2.1":     {name: "DH", primitive: "key-agree"},
	// post-quantum (FIPS 203/204/205)
	"2.16.840.1.101.3.4.4.1":  {name: "ML-KEM-512", primitive: "kem", pq: true},
	"2.16.840.1.101.3.4.4.2":  {name: "ML-KEM-768", primitive: "kem", pq: true},
	"2.16.840.1.101.3.4.4.3":  {name: "ML-KEM-1024", primitive: "kem", pq: true},
	"2.16.840.1.101.3.4.3.17": {name: "ML-DSA-44", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.18": {name: "ML-DSA-65", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.19": {name: "ML-DSA-87", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.20": {name: "SLH-DSA-SHA2-128s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.21": {name: "SLH-DSA-SHA2-128f", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.22": {name: "SLH-DSA-SHA2-192s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.23": {name: "SLH-DSA-SHA2-192f", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.24": {name: "SLH-DSA-SHA2-256s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.25": {name: "SLH-DSA-SHA2-256f", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.26": {name: "SLH-DSA-SHAKE-128s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.27": {name: "SLH-DSA-SHAKE-128f", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.28": {name: "SLH-DSA-SHAKE-192s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.29": {name: "SLH-DSA-SHAKE-192f", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.30": {name: "SLH-DSA-SHAKE-256s", primitive: "signature", pq: true},
	"2.16.840.1.101.3.4.3.31": {name: "SLH-DSA-SHAKE-256f", primitive: "signature", pq: true},
	// signatures (certificates, CMS)
	"1.2.840.113549.1.1.5":  {name: "SHA1-RSA", primitive: "signature"},
	"1.2.840.113549.1.1.11": {name: "SHA256-RSA", primitive: "signature"},
	"1.2.840.113549.1.1.12": {name: "SHA384-RSA", primitive: "signature"},
	"1.2.840.113549.1.1.13": {name: "SHA512-RSA", primitive: "signature"},
	"1.2.840.10045.4.3.2":   {name: "ECDSA-SHA256", primitive: "signature"},
	"1.2.840.10045.4.3.3":   {name: "ECDSA-SHA384", primitive: "signature"},
	"1.2.840.10045.4.3.4":   {name: "ECDSA-SHA512", primitive: "signature"},
	// CMS key agreement schemes (always classical: ECDH or DH)
	"1.3.133.16.840.63.0.2": {name: "ECDH (SHA-1 KDF)", primitive: "key-agree"},
	"1.3.132.1.11.0":        {name: "ECDH (SHA-224 KDF)", primitive: "key-agree"},
	"1.3.132.1.11.1":        {name: "ECDH (SHA-256 KDF)", primitive: "key-agree"},
	"1.3.132.1.11.2":        {name: "ECDH (SHA-384 KDF)", primitive: "key-agree"},
	"1.3.132.1.11.3":        {name: "ECDH (SHA-512 KDF)", primitive: "key-agree"},
	// content ciphers
	"2.16.840.1.101.3.4.1.2":     {name: "AES-128-CBC", primitive: "cipher", bits: 128, pq: true},
	"2.16.840.1.101.3.4.1.22":    {name: "AES-192-CBC", primitive: "cipher", bits: 192, pq: true},
	"2.16.840.1.101.3.4.1.42":    {name: "AES-256-CBC", primitive: "cipher", bits: 256, pq: true},
	"2.16.840.1.101.3.4.1.6":     {name: "AES-128-GCM", primitive: "cipher", bits: 128, pq: true},
	"2.16.840.1.101.3.4.1.26":    {name: "AES-192-GCM", primitive: "cipher", bits: 192, pq: true},
	"2.16.840.1.101.3.4.1.46":    {name: "AES-256-GCM", primitive: "cipher", bits: 256, pq: true},
	"2.16.840.1.101.3.4.1.7":     {name: "AES-128-CCM", primitive: "cipher", bits: 128, pq: true},
	"2.16.840.1.101.3.4.1.47":    {name: "AES-256-CCM", primitive: "cipher", bits: 256, pq: true},
	"2.16.840.1.101.3.4.1.5":     {name: "AES-128 key wrap", primitive: "cipher", bits: 128, pq: true},
	"2.16.840.1.101.3.4.1.25":    {name: "AES-192 key wrap", primitive: "cipher", bits: 192, pq: true},
	"2.16.840.1.101.3.4.1.45":    {name: "AES-256 key wrap", primitive: "cipher", bits: 256, pq: true},
	"1.2.840.113549.1.9.16.3.18": {name: "ChaCha20-Poly1305", primitive: "cipher", bits: 256, pq: true},
	"1.2.840.113549.3.7":         {name: "3DES-CBC", primitive: "cipher", bits: 168, legacy: true},
	"1.2.840.113549.3.2":         {name: "RC2-CBC", primitive: "cipher", legacy: true},
	"1.3.14.3.2.7":               {name: "DES-CBC", primitive: "cipher", bits: 56, legacy: true},
	"1.2.840.113549.1.9.16.3.6":  {name: "3DES key wrap", primitive: "cipher", legacy: true},
	"1.2.840.113549.1.5.13":      {name: "PBES2", primitive: "pbe"},
	"1.2.840.113549.1.5.12":      {name: "PBKDF2", primitive: "kdf"},
	"1.3.6.1.4.1.11591.4.11":     {name: "scrypt", primitive: "kdf"},
	"1.2.840.113549.1.5.3":       {name: "PBE-MD5-DES", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.5.10":      {name: "PBE-SHA1-DES", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.1":    {name: "PBE-SHA1-RC4-128", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.2":    {name: "PBE-SHA1-RC4-40", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.3":    {name: "PBE-SHA1-3DES", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.4":    {name: "PBE-SHA1-2DES", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.5":    {name: "PBE-SHA1-RC2-128", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.12.1.6":    {name: "PBE-SHA1-RC2-40", primitive: "pbe", legacy: true},
	"1.3.6.1.4.1.42.2.17.1.1":    {name: "JKS proprietary key protection", primitive: "pbe", legacy: true},
	"1.3.6.1.4.1.42.2.19.1":      {name: "PBE-MD5-3DES (JCEKS)", primitive: "pbe", legacy: true},
	"1.2.840.113549.1.9.16.13.3": {name: "KEMRecipientInfo", primitive: "kem"},
	"1.2.840.113549.1.9.16.3.28": {name: "HKDF-SHA256", primitive: "kdf"},
	"1.2.840.113549.1.9.16.3.29": {name: "HKDF-SHA384", primitive: "kdf"},
	"1.2.840.113549.1.9.16.3.30": {name: "HKDF-SHA512", primitive: "kdf"},
}

// curves maps named-curve OIDs to names (for EC keys and OpenPGP ECC keys).
var curves = map[string]string{
	"1.2.840.10045.3.1.7":    "P-256",
	"1.3.132.0.34":           "P-384",
	"1.3.132.0.35":           "P-521",
	"1.3.132.0.10":           "secp256k1",
	"1.3.36.3.3.2.8.1.1.7":   "brainpoolP256r1",
	"1.3.36.3.3.2.8.1.1.11":  "brainpoolP384r1",
	"1.3.36.3.3.2.8.1.1.13":  "brainpoolP512r1",
	"1.3.6.1.4.1.3029.1.5.1": "Curve25519",
	"1.3.6.1.4.1.11591.15.1": "Ed25519",
	"1.3.101.110":            "X25519",
	"1.3.101.112":            "Ed25519",
}

// lookup describes an OID, naming unknown ones by number.
func lookup(oid string) alg {
	if a, ok := oids[oid]; ok {
		return a
	}
	return alg{name: fmt.Sprintf("unrecognized algorithm (OID %s)", oid)}
}

// Content types and bag types.
const (
	oidData              = "1.2.840.113549.1.7.1"
	oidSignedData        = "1.2.840.113549.1.7.2"
	oidEnvelopedData     = "1.2.840.113549.1.7.3"
	oidEncryptedData     = "1.2.840.113549.1.7.6"
	oidAuthEnvelopedData = "1.2.840.113549.1.9.16.1.23"
	oidORIKEM            = "1.2.840.113549.1.9.16.13.3"
	oidPBES2             = "1.2.840.113549.1.5.13"
	oidPBKDF2            = "1.2.840.113549.1.5.12"
	oidKeyBag            = "1.2.840.113549.1.12.10.1.1"
	oidShroudedKeyBag    = "1.2.840.113549.1.12.10.1.2"
	oidCertBag           = "1.2.840.113549.1.12.10.1.3"
	oidECPublicKey       = "1.2.840.10045.2.1"
)
