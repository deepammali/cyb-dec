package inspect

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// age files (C2SP age v1). The header lists one stanza per recipient, each
// wrapping the same 128-bit file key; the payload is ChaCha20-Poly1305.

var ageStanzas = map[string]struct {
	class Class
	name  string
	prim  string
	conf  string
}{
	"X25519":          {ClassExposed, "X25519", "key-agree", "confirmed"},
	"p256tag":         {ClassExposed, "P-256 ECDH (hardware tag)", "key-agree", "confirmed"},
	"piv-p256":        {ClassExposed, "P-256 ECDH (YubiKey PIV plugin)", "key-agree", "confirmed"},
	"ssh-rsa":         {ClassExposed, "RSA (SSH key)", "key-transport", "confirmed"},
	"ssh-ed25519":     {ClassExposed, "X25519 from an Ed25519 SSH key", "key-agree", "confirmed"},
	"mlkem768x25519":  {ClassPQ, "ML-KEM-768 + X25519", "kem", "confirmed"},
	"mlkem768p256tag": {ClassPQ, "ML-KEM-768 + P-256 (hardware tag)", "kem", "confirmed"},
	"scrypt":          {ClassSymmetric, "scrypt passphrase", "kdf", "confirmed"},
}

const ageMagic = "age-encryption.org/v1\n"

func ageFinding(path string, b []byte, armored bool) (Finding, bool) {
	if !bytes.HasPrefix(b, []byte(ageMagic)) {
		return Finding{}, false
	}
	format := "age encrypted file"
	if armored {
		format += " (armored)"
	}
	f := Finding{Path: path, Format: format, Confidence: "confirmed"}
	counts := map[string]int{}
	var order []string
	sc := bufio.NewScanner(bytes.NewReader(b[len(ageMagic):]))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "---") {
			break
		}
		if !strings.HasPrefix(line, "-> ") {
			continue // stanza body
		}
		typ := strings.Fields(line[3:])
		if len(typ) == 0 {
			continue
		}
		if counts[typ[0]] == 0 {
			order = append(order, typ[0])
		}
		counts[typ[0]]++
	}
	var classical, pq, sym, unknown []string
	for _, t := range order {
		s, known := ageStanzas[t]
		label := t
		if known {
			label = s.name
		}
		if counts[t] > 1 {
			label = fmt.Sprintf("%s ×%d", label, counts[t])
		}
		f.fact("Recipient", fmt.Sprintf("%s (stanza %q)", label, t))
		switch {
		case !known:
			unknown = append(unknown, t)
		case s.class == ClassExposed:
			classical = append(classical, s.name)
			f.algo(Algorithm{Name: s.name, Primitive: s.prim, Role: "recipient"})
		case s.class == ClassPQ:
			pq = append(pq, s.name)
			f.algo(Algorithm{Name: s.name, Primitive: s.prim, Role: "recipient", PQ: true})
		default:
			sym = append(sym, s.name)
			f.algo(Algorithm{Name: "scrypt", Primitive: "kdf", Role: "key protection", PQ: true})
		}
	}
	f.fact("Payload", "ChaCha20-Poly1305, key derived from a 128-bit file key")
	f.algo(Algorithm{Name: "ChaCha20-Poly1305", Primitive: "cipher", Role: "content", PQ: true, Bits: 256})
	if len(unknown) > 0 {
		// Plugins name their own stanzas; today's hardware plugins use P-256 ECDH.
		classical = append(classical, "plugin "+strings.Join(unknown, ", "))
		if len(classical) == len(unknown) {
			f.Confidence = "low"
		}
		f.Limits = fmt.Sprintf("Unrecognized plugin stanza (%s): counted as classical because current age plugins use P-256 ECDH; check the plugin.", strings.Join(unknown, ", "))
	}
	f = classifyEnvelope(f, classical, pq, sym, "ChaCha20-Poly1305")
	if f.Class == ClassSymmetric {
		f.Headline = "Encrypted with a passphrase only (scrypt). No public-key step for a quantum computer to break."
		f.Protection = "scrypt passphrase → ChaCha20-Poly1305"
	}
	return f, true
}
