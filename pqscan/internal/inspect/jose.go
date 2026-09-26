package inspect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// JOSE tokens (JWE RFC 7516, JWS/JWT RFC 7515/7519) in text: logs, configs,
// captured headers. Only the protected header is decoded; the payload and
// signature never are, and tokens are never echoed.

var joseRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}={0,2}(?:\.[A-Za-z0-9_-]*={0,2}){2,4}`)

type joseClass struct {
	class Class
	name  string
	prim  string
	bits  int
	flags []string
}

func jweAlg(alg string) joseClass {
	switch {
	case alg == "RSA1_5":
		return joseClass{ClassExposed, "RSA PKCS#1 v1.5", "key-transport", 0, []string{FlagClassicalRecipient, FlagLegacyCipher}}
	case strings.HasPrefix(alg, "RSA-OAEP"):
		return joseClass{ClassExposed, alg, "key-transport", 0, []string{FlagClassicalRecipient}}
	case strings.HasPrefix(alg, "ECDH-ES"):
		return joseClass{ClassExposed, alg, "key-agree", 0, []string{FlagClassicalRecipient}}
	case strings.Contains(strings.ToUpper(alg), "MLKEM") || strings.Contains(strings.ToUpper(alg), "ML-KEM"):
		return joseClass{ClassPQ, alg, "kem", 0, nil}
	case alg == "dir":
		return joseClass{ClassSymmetric, "direct shared key", "cipher", 0, nil}
	case strings.HasPrefix(alg, "PBES2"):
		return joseClass{ClassSymmetric, alg + " (password)", "pbe", 0, nil}
	case strings.HasPrefix(alg, "A128"):
		return joseClass{ClassSymmetric, alg, "cipher", 128, []string{FlagAES128}}
	case strings.HasPrefix(alg, "A192"):
		return joseClass{ClassSymmetric, alg, "cipher", 192, nil}
	case strings.HasPrefix(alg, "A256"):
		return joseClass{ClassSymmetric, alg, "cipher", 256, nil}
	}
	return joseClass{ClassExposed, alg + " (unrecognized)", "", 0, nil}
}

func jwsAlg(alg string) joseClass {
	switch {
	case alg == "none":
		return joseClass{ClassWeak, "none (unsigned)", "signature", 0, []string{FlagLegacyCipher}}
	case strings.HasPrefix(alg, "HS"):
		return joseClass{ClassSymmetric, alg + " (HMAC)", "mac", 0, nil}
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return joseClass{ClassInventory, alg + " (RSA)", "signature", 0, []string{FlagClassicalKey}}
	case strings.HasPrefix(alg, "ES"):
		return joseClass{ClassInventory, alg + " (ECDSA)", "signature", 0, []string{FlagClassicalKey}}
	case alg == "EdDSA" || alg == "Ed25519" || alg == "Ed448":
		return joseClass{ClassInventory, alg, "signature", 0, []string{FlagClassicalKey}}
	case strings.HasPrefix(strings.ToUpper(alg), "ML-DSA") || strings.HasPrefix(strings.ToUpper(alg), "SLH-DSA"):
		return joseClass{ClassPQ, alg, "signature", 0, nil}
	}
	return joseClass{ClassInventory, alg + " (unrecognized)", "signature", 0, nil}
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// joseFindings aggregates the tokens in text by kind and algorithms.
func joseFindings(path string, text []byte) []Finding {
	type agg struct {
		jwe      bool
		alg, enc string
		count    int
	}
	found := map[string]*agg{}
	for _, m := range joseRE.FindAll(text, 100000) {
		parts := strings.Split(string(m), ".")
		if len(parts) != 3 && len(parts) != 5 {
			continue
		}
		hb, err := b64url(parts[0])
		if err != nil {
			continue
		}
		var h struct {
			Alg string `json:"alg"`
			Enc string `json:"enc"`
		}
		if json.Unmarshal(hb, &h) != nil || h.Alg == "" {
			continue
		}
		jwe := len(parts) == 5 && h.Enc != ""
		key := fmt.Sprintf("%v|%s|%s", jwe, h.Alg, h.Enc)
		if found[key] == nil {
			found[key] = &agg{jwe: jwe, alg: h.Alg, enc: h.Enc}
		}
		found[key].count++
	}
	var out []Finding
	for _, k := range sortedKeys(found) {
		a := found[k]
		f := Finding{Path: path, Confidence: "confirmed", Count: a.count}
		if a.jwe {
			c := jweAlg(a.alg)
			f.Format = "JWE token (encrypted)"
			f.fact("Key management (alg)", a.alg)
			f.fact("Content encryption (enc)", a.enc)
			f.Protection = c.name + " → " + a.enc
			f.Class = c.class
			f.flag(c.flags...)
			f.algo(Algorithm{Name: c.name, Primitive: c.prim, Role: "recipient", PQ: c.class == ClassPQ || c.class == ClassSymmetric, Bits: c.bits})
			bits := map[string]int{"A128": 128, "A192": 192, "A256": 256}[a.enc[:min(4, len(a.enc))]]
			f.algo(Algorithm{Name: a.enc, Primitive: "cipher", Role: "content", PQ: true, Bits: bits})
			if bits == 128 {
				f.flag(FlagAES128)
			}
			switch c.class {
			case ClassExposed:
				f.Headline = fmt.Sprintf("%d %s encrypted with %s: whoever records %s can decrypt the claims once a quantum computer breaks the key.", a.count, plural(a.count, "token", "tokens"), a.alg, plural(a.count, "it", "them"))
			case ClassPQ:
				f.Headline = fmt.Sprintf("%d %s encrypted with %s (post-quantum).", a.count, plural(a.count, "token", "tokens"), a.alg)
			default:
				f.Headline = fmt.Sprintf("%d %s encrypted with a symmetric key (%s): not exposed to harvest-now-decrypt-later.", a.count, plural(a.count, "token", "tokens"), a.alg)
			}
		} else {
			c := jwsAlg(a.alg)
			f.Format = "JWS/JWT token (signed)"
			f.fact("Signature (alg)", a.alg)
			f.Protection = c.name
			f.Class = c.class
			f.flag(c.flags...)
			f.algo(Algorithm{Name: c.name, Primitive: c.prim, Role: "signature", PQ: c.class == ClassPQ || c.class == ClassSymmetric})
			switch c.class {
			case ClassWeak:
				f.Headline = fmt.Sprintf("%d unsigned %s (alg none): anyone can forge %s.", a.count, plural(a.count, "token", "tokens"), plural(a.count, "it", "them"))
			case ClassSymmetric:
				f.Headline = fmt.Sprintf("%d %s signed with %s: a symmetric MAC, not affected by Shor's algorithm.", a.count, plural(a.count, "token", "tokens"), a.alg)
			case ClassPQ:
				f.Headline = fmt.Sprintf("%d %s signed with %s (post-quantum).", a.count, plural(a.count, "token", "tokens"), a.alg)
			default:
				f.Headline = fmt.Sprintf("%d %s signed with %s: signatures aren't a harvest-now-decrypt-later risk, but the signing keys must migrate. Readable claims are plaintext to anyone who sees the token.", a.count, plural(a.count, "token", "tokens"), c.name)
			}
		}
		f.Limits = "Only each token's protected header was decoded; tokens and claims are never stored or shown."
		out = append(out, f)
	}
	return out
}
