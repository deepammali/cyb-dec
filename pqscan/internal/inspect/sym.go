package inspect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Containers protected by symmetric keys or passwords: LUKS, KeePass, OpenSSL
// enc, Ansible Vault, SOPS (whose data key is wrapped per recipient), and
// encrypted ZIP entries.

func symFinding(f Finding, cipher string, bits int, legacy bool) Finding {
	f.algo(Algorithm{Name: cipher, Primitive: "cipher", Role: "content", PQ: !legacy, Bits: bits})
	switch {
	case legacy:
		f.Class = ClassWeak
		f.flag(FlagLegacyCipher)
	default:
		f.Class = ClassSymmetric
		if bits == 128 {
			f.flag(FlagAES128)
		}
	}
	return f
}

var luksMagic = []byte("LUKS\xba\xbe")

func luksFinding(path string, b []byte) (Finding, bool) {
	if !bytes.HasPrefix(b, luksMagic) || len(b) < 112 {
		return Finding{}, false
	}
	cstr := func(x []byte) string { return string(bytes.TrimRight(x, "\x00")) }
	version := binary.BigEndian.Uint16(b[6:8])
	f := Finding{Path: path, Confidence: "confirmed"}
	var cipher string
	var keyBytes int
	switch version {
	case 1:
		f.Format = "LUKS1 encrypted volume"
		cipher = cstr(b[8:40]) + "-" + cstr(b[40:72])
		keyBytes = int(binary.BigEndian.Uint32(b[108:112]))
		f.fact("Key derivation", "PBKDF2-"+cstr(b[72:104]))
	case 2:
		f.Format = "LUKS2 encrypted volume"
		hdr := int(binary.BigEndian.Uint64(b[8:16]))
		if hdr <= 4096 || len(b) < 4096 {
			return Finding{}, false
		}
		end := min(hdr, len(b))
		area := b[4096:end]
		if i := bytes.IndexByte(area, 0); i >= 0 {
			area = area[:i]
		}
		var meta struct {
			Keyslots map[string]struct {
				KeySize int `json:"key_size"`
				KDF     struct {
					Type string `json:"type"`
				} `json:"kdf"`
			} `json:"keyslots"`
			Segments map[string]struct {
				Encryption string `json:"encryption"`
			} `json:"segments"`
			Tokens map[string]struct {
				Type string `json:"type"`
			} `json:"tokens"`
		}
		if err := json.Unmarshal(area, &meta); err != nil {
			f.Confidence = "low"
			f.Limits = "The LUKS2 metadata area wasn't fully read, so the cipher is unknown."
			break
		}
		for _, k := range sortedKeys(meta.Segments) {
			cipher = meta.Segments[k].Encryption
			break
		}
		var kdfs []string
		for _, k := range sortedKeys(meta.Keyslots) {
			ks := meta.Keyslots[k]
			keyBytes = ks.KeySize
			kdfs = append(kdfs, ks.KDF.Type)
		}
		f.fact("Key derivation", strings.Join(uniq(kdfs), ", "))
		var tokens []string
		for _, k := range sortedKeys(meta.Tokens) {
			tokens = append(tokens, meta.Tokens[k].Type)
		}
		f.fact("Unlock tokens", strings.Join(tokens, ", "))
	default:
		return Finding{}, false
	}
	bits := keyBytes * 8
	if strings.Contains(cipher, "xts") {
		bits /= 2 // XTS uses two keys of half the size
	}
	f.fact("Cipher", cipher)
	if bits > 0 {
		f.fact("Key size", fmt.Sprintf("%d-bit", bits))
	}
	legacy := strings.HasPrefix(cipher, "des") || strings.Contains(cipher, "ecb") || strings.HasPrefix(cipher, "cast5") || strings.HasPrefix(cipher, "blowfish")
	f = symFinding(f, cipher, bits, legacy)
	f.Protection = fmt.Sprintf("passphrase or key file → %s", cipher)
	if bits > 0 {
		f.Protection += fmt.Sprintf(" (%d-bit)", bits)
	}
	switch {
	case legacy:
		f.Headline = "Disk encryption with a legacy cipher mode (" + cipher + "): re-encrypt the volume."
	case bits == 128:
		f.Headline = "Symmetric disk encryption with a 128-bit key: not exposed to harvest-now-decrypt-later; use 256-bit keys where CNSA 2.0 applies."
	default:
		f.Headline = "Symmetric disk encryption (" + cipher + "): not exposed to harvest-now-decrypt-later."
	}
	return f, true
}

// KeePass KDBX 3.1 and 4.x.
var (
	kdbxCiphers = map[string]struct {
		name string
		bits int
	}{
		"31c1f2e6bf714350be5805216afc5aff": {"AES-256", 256},
		"d6038a2b8b6f4cb5a524339a31dbb59a": {"ChaCha20", 256},
		"ad68f29f576f4bb9a36ad47af965346c": {"Twofish-256", 256},
	}
	kdbxKDFs = map[string]string{
		"c9d9f39a628a4460bf740d08c18a4fea": "AES-KDF",
		"7c02bb8279a74ac0927d114a00648238": "AES-KDF (KDBX 4)",
		"ef636ddf8c29444b91f7a9a403e30a0c": "Argon2d",
		"9e298b1956db4773b23dfc3ec6f0a1e6": "Argon2id",
	}
)

func kdbxFinding(path string, b []byte) (Finding, bool) {
	if len(b) < 12 || binary.LittleEndian.Uint32(b) != 0x9AA2D903 || binary.LittleEndian.Uint32(b[4:]) != 0xB54BFB67 {
		return Finding{}, false
	}
	major := int(binary.LittleEndian.Uint16(b[10:12]))
	f := Finding{Path: path, Format: fmt.Sprintf("KeePass database (KDBX %d)", major), Confidence: "confirmed"}
	cipher := struct {
		name string
		bits int
	}{"unknown cipher", 0}
	kdf := "AES-KDF"
	p := 12
	for p < len(b) {
		id := b[p]
		var l int
		if major >= 4 {
			if p+5 > len(b) {
				break
			}
			l, p = int(binary.LittleEndian.Uint32(b[p+1:])), p+5
		} else {
			if p+3 > len(b) {
				break
			}
			l, p = int(binary.LittleEndian.Uint16(b[p+1:])), p+3
		}
		if l < 0 || p+l > len(b) {
			break
		}
		v := b[p : p+l]
		p += l
		switch id {
		case 0:
			p = len(b)
		case 2:
			if c, ok := kdbxCiphers[hex.EncodeToString(v)]; ok {
				cipher = c
			}
		case 11: // KDF parameters (variant dictionary)
			if i := bytes.Index(v, []byte("$UUID")); i >= 0 && i+5+4+16 <= len(v) {
				if name, ok := kdbxKDFs[hex.EncodeToString(v[i+9:i+25])]; ok {
					kdf = name
				}
			}
		}
	}
	f.fact("Cipher", cipher.name)
	f.fact("Key derivation", kdf)
	f = symFinding(f, cipher.name, cipher.bits, false)
	f.Protection = "master password → " + cipher.name
	f.Headline = "Password database encrypted with " + cipher.name + ": not exposed to harvest-now-decrypt-later; strength rests on the master password."
	return f, true
}

func opensslEncFinding(path string, b []byte) (Finding, bool) {
	if !bytes.HasPrefix(b, []byte("Salted__")) || len(b) < 16 {
		return Finding{}, false
	}
	f := Finding{Path: path, Format: "OpenSSL enc file", Confidence: "high", Class: ClassSymmetric, Protection: "passphrase → undeclared cipher"}
	f.flag(FlagUndeclaredCipher)
	f.fact("Header", "Salted__ + 8-byte salt")
	f.Headline = "Passphrase-encrypted with openssl enc. Not exposed to harvest-now-decrypt-later, but the file doesn't record its cipher or key derivation."
	f.Limits = "openssl enc stores neither the cipher nor the KDF. Without -pbkdf2, older scripts derive the key with a single MD5 pass, which makes the passphrase cheap to brute-force."
	f.algo(Algorithm{Name: "undeclared cipher", Primitive: "cipher", Role: "content"})
	return f, true
}

var ansibleRE = regexp.MustCompile(`^\$ANSIBLE_VAULT;(1\.[12]);([A-Z0-9]+)`)

func ansibleFinding(path string, b []byte) (Finding, bool) {
	m := ansibleRE.FindSubmatch(b)
	if m == nil {
		return Finding{}, false
	}
	f := Finding{Path: path, Format: "Ansible Vault file", Confidence: "confirmed"}
	cipher := string(m[2])
	f.fact("Format version", string(m[1]))
	f.fact("Cipher", cipher+" (AES-256-CTR, PBKDF2-SHA256 key derivation)")
	f = symFinding(f, "AES-256-CTR", 256, cipher != "AES256")
	f.Protection = "vault password → AES-256-CTR"
	f.Headline = "Encrypted with a vault password (AES-256): not exposed to harvest-now-decrypt-later."
	return f, true
}

// SOPS: values are encrypted with a data key (AES256_GCM), and the data key is
// wrapped once per key group entry: age, PGP, or a cloud KMS.
var (
	sopsMarkerRE = regexp.MustCompile(`ENC\[AES256_GCM,`)
	sopsAgeRE    = regexp.MustCompile(`recipient["']?\s*[:=]\s*["']?(age1[0-9a-z]+)`)
	sopsPGPRE    = regexp.MustCompile(`\bfp["']?\s*[:=]\s*["']?([0-9A-Fa-f]{16,40})`)
	sopsKMSRE    = regexp.MustCompile(`\barn["']?\s*[:=]\s*["']?(arn:aws[a-z-]*:kms:[^\s"',]+)`)
	sopsGCPRE    = regexp.MustCompile(`\bresource_id["']?\s*[:=]\s*["']?(projects/[^\s"',]+)`)
	sopsAzureRE  = regexp.MustCompile(`\bvault_url["']?\s*[:=]\s*["']?(https://[^\s"',]+)`)
	sopsVaultRE  = regexp.MustCompile(`\bvault_address["']?\s*[:=]\s*["']?(https?://[^\s"',]+)`)
)

func sopsFinding(path string, b []byte) (Finding, bool) {
	if !sopsMarkerRE.Match(b) || !bytes.Contains(b, []byte("sops")) {
		return Finding{}, false
	}
	f := Finding{Path: path, Format: "SOPS encrypted file", Confidence: "confirmed"}
	var classical, pq, sym []string
	count := func(re *regexp.Regexp) int { return len(re.FindAllSubmatch(b, 1000)) }
	for _, m := range sopsAgeRE.FindAllSubmatch(b, 1000) {
		r := string(m[1])
		if strings.HasPrefix(r, "age1pq1") || strings.HasPrefix(r, "age1tagpq1") {
			pq = append(pq, "age ML-KEM-768 hybrid")
		} else {
			classical = append(classical, "age X25519")
		}
	}
	if n := count(sopsPGPRE); n > 0 {
		classical = append(classical, "OpenPGP key")
		f.Confidence = "high"
		f.Limits = "OpenPGP recipients are listed by fingerprint only; they are counted as classical because OpenPGP keys are, unless created with the RFC 9980 ML-KEM algorithms."
	}
	if n := count(sopsAzureRE); n > 0 {
		classical = append(classical, "Azure Key Vault (RSA-OAEP key wrap)")
	}
	if n := count(sopsKMSRE); n > 0 {
		sym = append(sym, "AWS KMS")
	}
	if n := count(sopsGCPRE); n > 0 {
		sym = append(sym, "GCP KMS")
	}
	if n := count(sopsVaultRE); n > 0 {
		sym = append(sym, "HashiCorp Vault transit")
	}
	for _, c := range uniq(classical) {
		f.fact("Data key wrapped by", c)
		f.algo(Algorithm{Name: c, Primitive: "key-agree", Role: "recipient"})
	}
	for _, c := range uniq(pq) {
		f.fact("Data key wrapped by", c)
		f.algo(Algorithm{Name: c, Primitive: "kem", Role: "recipient", PQ: true})
	}
	for _, c := range uniq(sym) {
		f.fact("Data key wrapped by", c+" (symmetric key in the service)")
		f.algo(Algorithm{Name: c, Primitive: "cipher", Role: "key protection", PQ: true})
	}
	f.fact("Values", "AES-256-GCM")
	f.algo(Algorithm{Name: "AES-256-GCM", Primitive: "cipher", Role: "content", PQ: true, Bits: 256})
	f = classifyEnvelope(f, classical, pq, sym, "AES-256-GCM")
	if f.Class == ClassSymmetric {
		f.Headline = "The data key is wrapped only by symmetric keys in a KMS: not exposed to harvest-now-decrypt-later."
		f.Protection = strings.Join(uniq(sym), " + ") + " → AES-256-GCM"
	}
	return f, true
}

// zipEncryption summarizes a ZIP archive's encrypted entries.
type zipEnc struct {
	aes     map[int]int // key bits → entries
	zipCryp int
	strong  int
	names   []string
}

func (z *zipEnc) finding(path string) (Finding, bool) {
	total := z.zipCryp + z.strong
	for _, n := range z.aes {
		total += n
	}
	if total == 0 {
		return Finding{}, false
	}
	f := Finding{Path: path, Format: "Encrypted ZIP archive", Confidence: "confirmed"}
	var parts []string
	worst := 256
	for _, bits := range []int{128, 192, 256} {
		if n := z.aes[bits]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d with AES-%d (WinZip AE)", n, bits))
			f.algo(Algorithm{Name: fmt.Sprintf("AES-%d", bits), Primitive: "cipher", Role: "content", PQ: true, Bits: bits})
			worst = min(worst, bits)
		}
	}
	if z.strong > 0 {
		parts = append(parts, fmt.Sprintf("%d with PKWARE strong encryption", z.strong))
	}
	if z.zipCryp > 0 {
		parts = append(parts, fmt.Sprintf("%d with ZipCrypto", z.zipCryp))
		f.algo(Algorithm{Name: "ZipCrypto", Primitive: "cipher", Role: "content"})
	}
	f.fact("Encrypted entries", strings.Join(parts, "; "))
	f.Protection = "password → " + strings.Join(parts, ", ")
	switch {
	case z.zipCryp > 0:
		f.Class = ClassWeak
		f.flag(FlagLegacyCipher)
		f.Headline = fmt.Sprintf("%d %s ZipCrypto, which known-plaintext attacks break in hours: re-create the archive with AES-256.", z.zipCryp, plural(z.zipCryp, "entry uses", "entries use"))
	case worst == 128:
		f.Class = ClassSymmetric
		f.flag(FlagAES128)
		f.Headline = "Password-encrypted with AES-128: not exposed to harvest-now-decrypt-later; use AES-256 where CNSA 2.0 applies."
	default:
		f.Class = ClassSymmetric
		f.Headline = "Password-encrypted with AES: not exposed to harvest-now-decrypt-later."
	}
	f.Limits = "Encrypted entries were not opened."
	return f, true
}
