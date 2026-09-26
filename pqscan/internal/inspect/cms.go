package inspect

import (
	"fmt"
	"strings"
)

// CMS / S/MIME (RFC 5652, KEMRecipientInfo RFC 9629) and PKCS#12 (RFC 7292).

// pbeDesc describes a key-protection AlgorithmIdentifier, expanding PBES2 to
// its KDF and cipher.
func pbeDesc(n node) (string, alg) {
	oid, params := n.algorithm()
	a := lookup(oid)
	if oid != oidPBES2 || len(params) == 0 {
		return a.name, a
	}
	c := params[0].children() // PBES2-params: { keyDerivationFunc, encryptionScheme }
	if len(c) < 2 {
		return "PBES2", a
	}
	kdfOID, _ := c[0].algorithm()
	encOID, _ := c[1].algorithm()
	kdf, enc := lookup(kdfOID), lookup(encOID)
	return fmt.Sprintf("PBES2 (%s, %s)", kdf.name, enc.name), enc
}

// rsaBits reads the modulus size from an RSAPublicKey or RSAPrivateKey body.
func rsaBits(seq node, index int) int {
	c := seq.children()
	if len(c) <= index || !c[index].is(classUniversal, tagInteger) {
		return 0
	}
	b := c[index].body
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	bits := (len(b) - 1) * 8
	for x := b[0]; x > 0; x >>= 1 {
		bits++
	}
	return bits
}

// cmsFinding describes a CMS ContentInfo. ok is false when n isn't one.
func cmsFinding(path string, n node) (Finding, bool) {
	c := n.children()
	if len(c) < 2 || !c[1].is(classContext, 0) {
		return Finding{}, false
	}
	inner := c[1].children()
	if len(inner) == 0 {
		return Finding{}, false
	}
	switch c[0].oid() {
	case oidEnvelopedData:
		return cmsEnveloped(path, inner[0], "CMS EnvelopedData (S/MIME encrypted)"), true
	case oidAuthEnvelopedData:
		return cmsEnveloped(path, inner[0], "CMS AuthEnvelopedData (S/MIME encrypted)"), true
	case oidEncryptedData:
		return cmsEncryptedData(path, inner[0]), true
	case oidSignedData:
		return cmsSigned(path, inner[0])
	}
	return Finding{}, false
}

func cmsEnveloped(path string, env node, format string) Finding {
	f := Finding{Path: path, Format: format, Confidence: "confirmed"}
	var classical, pq, sym []string
	var content alg
	for _, x := range env.children() {
		switch {
		case x.is(classUniversal, tagSet):
			for _, ri := range x.children() {
				desc, a, kind := cmsRecipient(ri)
				if desc == "" {
					continue
				}
				f.fact("Recipient", desc)
				switch kind {
				case "classical":
					classical = append(classical, a.name)
					f.algo(Algorithm{Name: a.name, Primitive: a.primitive, Role: "recipient"})
				case "pq":
					pq = append(pq, a.name)
					f.algo(Algorithm{Name: a.name, Primitive: "kem", Role: "recipient", PQ: true})
				default:
					sym = append(sym, desc)
					f.algo(Algorithm{Name: a.name, Primitive: a.primitive, Role: "key protection", PQ: a.pq, Bits: a.bits})
					if a.legacy {
						f.flag(FlagLegacyCipher)
					}
				}
			}
		case x.isSeq() && content.name == "":
			// EncryptedContentInfo { contentType, contentEncryptionAlgorithm, [0] content }
			ec := x.children()
			if len(ec) >= 2 && ec[0].oid() != "" {
				oid, _ := ec[1].algorithm()
				content = lookup(oid)
			}
		}
	}
	if content.name != "" {
		f.fact("Content cipher", content.name)
		f.algo(Algorithm{Name: content.name, Primitive: "cipher", Role: "content", PQ: content.pq, Bits: content.bits})
		if content.legacy {
			f.flag(FlagLegacyCipher)
		} else if content.bits == 128 {
			f.flag(FlagAES128)
		}
	}
	return classifyEnvelope(f, classical, pq, sym, content.name)
}

// classifyEnvelope applies the exposure rule to an encrypted artifact's recipients.
func classifyEnvelope(f Finding, classical, pq, sym []string, content string) Finding {
	who := strings.Join(uniq(append(append([]string{}, classical...), pq...)), " + ")
	switch {
	case len(classical) > 0:
		f.Class = ClassExposed
		f.flag(FlagClassicalRecipient)
		f.Headline = fmt.Sprintf("Encrypted to %s. Anyone who keeps a copy can decrypt it once a quantum computer breaks %s.",
			strings.Join(uniq(classical), " and "), strings.Join(uniq(baseNames(classical)), " and "))
		if len(pq) > 0 {
			f.Headline += " The ML-KEM recipient doesn't help: any one recipient's key opens the content."
		}
	case len(pq) > 0:
		f.Class = ClassPQ
		f.Headline = fmt.Sprintf("Encrypted to %s only: not exposed to harvest-now-decrypt-later.", strings.Join(uniq(pq), " and "))
	case len(sym) > 0:
		f.Class = ClassSymmetric
		who = "symmetric key"
		f.Headline = "Protected by a pre-shared key or password only: no public-key step for a quantum computer to break."
	default:
		f.Class = ClassSymmetric
		f.Confidence = "high"
		who = "unknown recipients"
		f.Headline = "Encrypted, but no recipient could be read from the header."
	}
	if f.Class != ClassExposed && f.has(FlagLegacyCipher) {
		f.Class = ClassWeak
		f.Headline = "Uses a legacy cipher (" + content + "): weak today, before any quantum computer."
	}
	f.Protection = who
	if content != "" {
		f.Protection += " → " + content
	}
	return f
}

// cmsRecipient describes one RecipientInfo and whether it is classical, pq, or symmetric.
func cmsRecipient(ri node) (string, alg, string) {
	c := ri.children()
	switch {
	case ri.isSeq(): // KeyTransRecipientInfo
		if len(c) >= 3 {
			oid, _ := c[2].algorithm()
			a := lookup(oid)
			return fmt.Sprintf("key transport, %s", a.name), a, "classical"
		}
	case ri.is(classContext, 1): // KeyAgreeRecipientInfo
		for _, x := range c {
			if x.isSeq() {
				oid, params := x.algorithm()
				a := lookup(oid)
				d := "key agreement, " + a.name
				if len(params) > 0 {
					if w, _ := params[0].algorithm(); w != "" {
						d += ", wrap " + lookup(w).name
					}
				}
				a.primitive = "key-agree"
				return d, a, "classical"
			}
		}
		return "key agreement (ECDH/DH)", alg{name: "ECDH", primitive: "key-agree"}, "classical"
	case ri.is(classContext, 2): // KEKRecipientInfo
		if len(c) >= 3 {
			oid, _ := c[2].algorithm()
			a := lookup(oid)
			return "pre-shared key-encryption key, " + a.name, a, "symmetric"
		}
	case ri.is(classContext, 3): // PasswordRecipientInfo
		for _, x := range c {
			if x.isSeq() {
				oid, params := x.algorithm()
				a := lookup(oid)
				if a.name == "PWRI-KEK" && len(params) > 0 { // name the wrapping cipher it carries
					if inner, _ := params[0].algorithm(); inner != "" {
						a = lookup(inner)
						return "password, PWRI-KEK with " + a.name, a, "symmetric"
					}
				}
				return "password, " + a.name, a, "symmetric"
			}
		}
	case ri.is(classContext, 4): // OtherRecipientInfo
		if len(c) >= 2 && c[0].oid() == oidORIKEM {
			k := c[1].children() // KEMRecipientInfo { version, rid, kem, kemct, kdf, kekLength, [ukm], wrap, encryptedKey }
			if len(k) >= 3 {
				oid, _ := k[2].algorithm()
				a := lookup(oid)
				if a.pq {
					return "KEM, " + a.name, a, "pq"
				}
				return "KEM, " + a.name, a, "classical"
			}
		}
		if len(c) >= 1 {
			return "other recipient type " + c[0].oid(), alg{name: "unknown recipient type"}, "classical"
		}
	}
	return "", alg{}, ""
}

func cmsEncryptedData(path string, ed node) Finding {
	f := Finding{Path: path, Format: "CMS EncryptedData", Confidence: "confirmed"}
	var content alg
	for _, x := range ed.children() {
		if x.isSeq() {
			if ec := x.children(); len(ec) >= 2 {
				desc, a := pbeDesc(ec[1])
				content = a
				f.fact("Content cipher", desc)
			}
		}
	}
	f.algo(Algorithm{Name: content.name, Primitive: "cipher", Role: "content", PQ: content.pq, Bits: content.bits})
	if content.legacy {
		f.flag(FlagLegacyCipher)
	} else if content.bits == 128 {
		f.flag(FlagAES128)
	}
	return classifyEnvelope(f, nil, nil, []string{"pre-shared key"}, content.name)
}

func cmsSigned(path string, sd node) (Finding, bool) {
	f := Finding{Path: path, Format: "CMS SignedData (S/MIME signature)", Confidence: "confirmed"}
	var sigs []alg
	certs := 0
	for _, x := range sd.children() {
		switch {
		case x.is(classContext, 0):
			certs = len(x.children())
		case x.is(classUniversal, tagSet):
			for _, si := range x.children() {
				// SignerInfo: ..., signatureAlgorithm, signature OCTET STRING, [1] unsignedAttrs.
				c := si.children()
				for k := 1; si.isSeq() && k < len(c); k++ {
					if c[k].is(classUniversal, tagOctetString) {
						if oid, _ := c[k-1].algorithm(); oid != "" {
							sigs = append(sigs, lookup(oid))
						}
						break
					}
				}
			}
		}
	}
	if len(sigs) == 0 {
		return Finding{}, false
	}
	var names []string
	pq := true
	for _, a := range sigs {
		names = append(names, a.name)
		f.algo(Algorithm{Name: a.name, Primitive: "signature", Role: "signature", PQ: a.pq})
		pq = pq && a.pq
	}
	f.Protection = strings.Join(uniq(names), ", ")
	f.fact("Signature", f.Protection)
	if certs > 0 {
		f.fact("Certificates included", fmt.Sprint(certs))
	}
	if pq {
		f.Class = ClassPQ
		f.Headline = "Post-quantum signature (" + f.Protection + ")."
	} else {
		f.Class = ClassInventory
		f.flag(FlagClassicalKey)
		f.Headline = "Classical signature (" + f.Protection + "): not a harvest-now-decrypt-later risk; signers need to migrate to ML-DSA."
	}
	return f, true
}

// pkcs12Finding describes a PFX. ok is false when n isn't one.
func pkcs12Finding(path string, n node) (Finding, bool) {
	c := n.children()
	if len(c) < 2 || !c[0].is(classUniversal, tagInteger) || len(c[0].body) != 1 || c[0].body[0] != 3 || !c[1].isSeq() {
		return Finding{}, false
	}
	auth := c[1].children()
	if len(auth) < 2 || auth[0].oid() != oidData || !auth[1].is(classContext, 0) {
		return Finding{}, false
	}
	f := Finding{Path: path, Format: "PKCS#12 key store", Confidence: "confirmed", Class: ClassInventory}
	octets := auth[1].children()
	if len(octets) == 0 {
		return f, true
	}
	safe, _, err := parseNode(octets[0].body)
	if err != nil {
		return f, true
	}
	var protections []string
	var keys []string
	for _, ci := range safe.children() { // AuthenticatedSafe: SEQUENCE OF ContentInfo
		cc := ci.children()
		if len(cc) < 2 {
			continue
		}
		switch cc[0].oid() {
		case oidEncryptedData:
			if in := cc[1].children(); len(in) > 0 {
				for _, x := range in[0].children() {
					if x.isSeq() {
						if ec := x.children(); len(ec) >= 2 {
							desc, a := pbeDesc(ec[1])
							protections = append(protections, desc)
							f.fact("Encrypted bag (certificates)", desc)
							p12Protect(&f, a)
						}
					}
				}
			}
		case oidData:
			if in := cc[1].children(); len(in) > 0 {
				bags, _, err := parseNode(in[0].body)
				if err != nil {
					continue
				}
				for _, bag := range bags.children() {
					bc := bag.children()
					if len(bc) < 2 {
						continue
					}
					val := bc[1].children()
					if len(val) == 0 {
						continue
					}
					switch bc[0].oid() {
					case oidShroudedKeyBag:
						if ek := val[0].children(); len(ek) >= 1 {
							desc, a := pbeDesc(ek[0])
							protections = append(protections, desc)
							f.fact("Private key bag", "encrypted with "+desc)
							p12Protect(&f, a)
						}
					case oidKeyBag:
						if pk := val[0].children(); len(pk) >= 2 {
							oid, _ := pk[1].algorithm()
							keys = append(keys, lookup(oid).name)
							f.fact("Private key bag", lookup(oid).name+", not encrypted")
							f.flag(FlagPlainPrivateKey, FlagClassicalKey)
						}
					case oidCertBag:
						if cv := val[0].children(); len(cv) >= 2 {
							if der := cv[1].children(); len(der) > 0 {
								if cert, _, err := parseNode(der[0].body); err == nil {
									if cf, ok := certFinding(path, cert); ok {
										keys = append(keys, cf.Protection)
										f.fact("Certificate", cf.Protection)
										f.Algorithms = append(f.Algorithms, cf.Algorithms...)
										f.flag(cf.Flags...)
									}
								}
							}
						}
					}
				}
			}
		case oidEnvelopedData:
			f.fact("Public-key privacy mode", "contents encrypted to a recipient's public key")
			f.flag(FlagClassicalRecipient)
		}
	}
	f.Protection = strings.Join(uniq(protections), " + ")
	if len(keys) > 0 {
		f.Protection = strings.Join(uniq(keys), ", ") + " · " + f.Protection
	}
	switch {
	case f.has(FlagLegacyCipher):
		f.Class = ClassWeak
		f.Headline = "Protected with a legacy PKCS#12 cipher (" + strings.Join(uniq(protections), ", ") + "): brute-forceable today. Re-export with AES-256."
	default:
		f.flag(FlagClassicalKey)
		f.Headline = "Private key store. Its keys and certificates are classical unless issued with ML-DSA or ML-KEM; plan their migration."
		f.Confidence = "high"
		f.Limits = "The private key's algorithm is inside the encrypted bag and can't be read without the password."
	}
	return f, true
}

func p12Protect(f *Finding, a alg) {
	f.algo(Algorithm{Name: a.name, Primitive: "pbe", Role: "key protection", PQ: a.pq, Bits: a.bits})
	if a.legacy {
		f.flag(FlagLegacyCipher)
	}
}
