// Package inspect finds cryptographic artifacts in data at rest (files,
// archives, mail) and classifies how exposed each is to a quantum attacker.
//
// The rule it applies: data is harvest-now-decrypt-later exposed exactly when
// the key that decrypts it was established or wrapped with a classical
// public-key algorithm (RSA, ECDH, X25519, ElGamal). Self-describing formats
// declare that in cleartext headers so recipients know how to decrypt, so the
// inspector reads headers only. It never decrypts, never needs a password, and
// never reports key material or content.
package inspect

// Class is how exposed an artifact is.
type Class string

const (
	ClassExposed   Class = "exposed"   // key established or wrapped with classical public-key crypto
	ClassWeak      Class = "weak"      // protection broken or deprecated today, quantum or not
	ClassPQ        Class = "pq"        // key established with ML-KEM, or post-quantum keys and signatures
	ClassSymmetric Class = "symmetric" // protected only by symmetric keys or passwords
	ClassInventory Class = "inventory" // classical keys, certificates, and signatures to migrate
)

// ClassOrder lists classes from most to least urgent.
var ClassOrder = []Class{ClassExposed, ClassWeak, ClassInventory, ClassSymmetric, ClassPQ}

// Flags name specific problems; recommendations are derived from them.
const (
	FlagClassicalRecipient = "classical-recipient"      // wrapped to RSA/ECDH/X25519/ElGamal
	FlagLegacyCipher       = "legacy-cipher"            // 3DES, RC2, RC4, DES, CAST5, Blowfish, IDEA, ZipCrypto, JKS
	FlagNoIntegrity        = "no-integrity"             // OpenPGP SED packet: malleable
	FlagAES128             = "aes128"                   // 128-bit symmetric key the owner chose
	FlagClassicalKey       = "classical-key"            // classical private/public key or certificate
	FlagClassicalEncKey    = "classical-encryption-key" // data encrypted to this key is exposed
	FlagPlainPrivateKey    = "unencrypted-private-key"
	FlagUndeclaredCipher   = "undeclared-cipher" // the container doesn't say how it is encrypted
)

// Fact is one interpreted header field.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Algorithm is one cryptographic algorithm an artifact uses, for inventories.
type Algorithm struct {
	Name      string `json:"name"`
	Primitive string `json:"primitive"` // kem, key-agree, key-transport, signature, cipher, kdf, pbe, mac
	Role      string `json:"role"`      // recipient, content, key protection, public key, signature
	PQ        bool   `json:"pq,omitempty"`
	Bits      int    `json:"bits,omitempty"`
}

// Finding is one artifact and its assessment.
type Finding struct {
	Path       string      `json:"path"`
	Format     string      `json:"format"`
	Class      Class       `json:"class"`
	Protection string      `json:"protection"` // one line, e.g. "RSA → AES-256"
	Headline   string      `json:"headline"`
	Evidence   []Fact      `json:"evidence"`
	Algorithms []Algorithm `json:"algorithms,omitempty"`
	Confidence string      `json:"confidence"` // confirmed (header parsed per spec), high, low
	Limits     string      `json:"limits,omitempty"`
	Count      int         `json:"count,omitempty"` // occurrences folded into this finding (tokens in a log)
	Flags      []string    `json:"flags,omitempty"`
}

func (f *Finding) fact(label, value string) {
	if value != "" {
		f.Evidence = append(f.Evidence, Fact{label, value})
	}
}

func (f *Finding) flag(flags ...string) {
	for _, fl := range flags {
		if !f.has(fl) {
			f.Flags = append(f.Flags, fl)
		}
	}
}

func (f *Finding) has(flag string) bool {
	for _, x := range f.Flags {
		if x == flag {
			return true
		}
	}
	return false
}

func (f *Finding) algo(a Algorithm) { f.Algorithms = append(f.Algorithms, a) }

// Skip records something the inspector did not read, and why.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
