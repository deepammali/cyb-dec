package cbom

import (
	"fmt"
	"strings"
	"time"

	"pqscan/internal/inspect"
	"pqscan/internal/observe"
	"pqscan/internal/report"
)

// AddHost records a probe of one host: a protocol asset per reachable
// service, with its negotiated algorithms and certificate.
func (b *Builder) AddHost(hr report.HostReport) {
	b.Property("pqscan:mode", "probe")
	b.Property("pqscan:target", hr.Host)
	b.Property("pqscan:verdict", string(hr.Verdict))
	b.hostServices(hr)
}

// AddEstate records every host of an estate scan.
func (b *Builder) AddEstate(er report.EstateReport) {
	b.Property("pqscan:mode", "estate")
	b.Property("pqscan:verdict", string(er.Verdict))
	b.Property("pqscan:headline", er.Headline)
	for _, hr := range er.Hosts {
		b.hostServices(hr)
	}
}

func (b *Builder) hostServices(hr report.HostReport) {
	for _, s := range hr.Services {
		if s.State != report.StatePQ && s.State != report.StateClassical {
			continue // closed, silent, errors, and plaintext have no cryptography to list
		}
		loc := fmt.Sprintf("%s:%d", s.Host, s.Port)
		if len(s.Addresses) > 0 {
			loc += " (" + strings.Join(s.Addresses, ", ") + ")"
		}
		ctx := s.Service
		props := []Property{{"pqscan:state", string(s.State)}, {"pqscan:confidence", string(s.Assessment.Confidence)}, {"pqscan:headline", s.Headline}}
		if s.Kind == "ssh" {
			var refs []string
			for _, k := range s.Advertised {
				if r := b.Algorithm(k, "key-agree", strings.Contains(k, "mlkem") || strings.Contains(k, "sntrup"), 0, loc, ctx+": advertised key exchange"); r != "" {
					refs = append(refs, r)
				}
			}
			b.add(Component{Name: fmt.Sprintf("SSH %s", loc), Description: s.Service,
				CryptoProperties: &CryptoProperties{AssetType: "protocol", ProtocolProperties: &ProtocolProperties{Type: "ssh", Version: "2.0", CryptoRefArray: refs}},
				Evidence:         &Evidence{Occurrences: []Occurrence{{Location: loc, AdditionalContext: s.Banner}}}, Properties: props}, "crypto/protocol/ssh/"+loc)
			continue
		}
		var refs []string
		group := b.Algorithm(strings.TrimSuffix(s.NegotiatedGroup, " (TLS 1.2)"), "key-agree", s.State == report.StatePQ, 0, loc, ctx+": negotiated key exchange")
		if group != "" {
			refs = append(refs, group)
		}
		for _, g := range s.Groups {
			if g.Supported {
				if r := b.Algorithm(g.Group, "kem", true, 0, loc, ctx+": supported"); r != "" && r != group {
					refs = append(refs, r)
				}
			}
		}
		suite := CipherSuite{Name: s.CipherSuite}
		for _, a := range suiteAlgorithms(s.CipherSuite) {
			if r := b.Algorithm(a, "cipher", true, 0, loc, ctx+": cipher suite"); r != "" {
				suite.Algorithms = append(suite.Algorithms, r)
			}
		}
		if group != "" {
			suite.Algorithms = append(suite.Algorithms, group)
		}
		pp := &ProtocolProperties{Type: "tls", Version: strings.TrimPrefix(s.TLSVersion, "TLS "), CryptoRefArray: refs}
		if s.CipherSuite != "" {
			pp.CipherSuites = []CipherSuite{suite}
		}
		b.add(Component{Name: fmt.Sprintf("%s %s", orDefault(s.TLSVersion, "TLS"), loc), Description: s.Service,
			CryptoProperties: &CryptoProperties{AssetType: "protocol", ProtocolProperties: pp},
			Evidence:         &Evidence{Occurrences: []Occurrence{{Location: loc, AdditionalContext: ctx}}}, Properties: props}, "crypto/protocol/tls/"+loc)
		if s.CertSigAlg != "" {
			sig := b.Algorithm(s.CertSigAlg, "signature", false, 0, loc, ctx+": certificate signature")
			subject := ""
			if s.CertSubject != "" {
				subject = "CN=" + s.CertSubject
			}
			b.add(Component{Name: "Certificate " + orDefault(subject, loc),
				CryptoProperties: &CryptoProperties{AssetType: "certificate", CertificateProperties: &CertificateProperties{
					SubjectName: subject, NotValidAfter: dateTime(s.CertNotAfter), SignatureAlgorithmRef: sig, CertificateFormat: "X.509"}},
				Evidence: &Evidence{Occurrences: []Occurrence{{Location: loc, AdditionalContext: ctx + ": server certificate"}}}}, "crypto/certificate/"+loc)
		}
	}
}

// dateTime passes through RFC 3339 timestamps (the schema's date-time) and drops anything else.
func dateTime(s string) string {
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return ""
	}
	return s
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// AddInspect records data at rest: each finding's algorithms, and the artifact
// itself as a certificate, key, signature, token, or ciphertext.
func (b *Builder) AddInspect(r inspect.Report) {
	b.Property("pqscan:mode", "inspect")
	b.Property("pqscan:verdict", string(r.Verdict))
	b.Property("pqscan:headline", r.Headline)
	for _, f := range r.Findings {
		b.AddFinding(f)
	}
}

// materialType maps a finding's format to a CycloneDX related-crypto-material type.
func materialType(format string) string {
	f := strings.ToLower(format)
	switch {
	case strings.Contains(f, "certificate") && !strings.Contains(f, "request"):
		return "certificate"
	case strings.Contains(f, "jwe"), strings.Contains(f, "jws"):
		return "token"
	case strings.Contains(f, "signature"):
		return "signature"
	case strings.Contains(f, "private key"), strings.Contains(f, "secret key"), strings.Contains(f, "identity"),
		strings.Contains(f, "key store"), strings.Contains(f, "keystore"):
		return "private-key"
	case strings.Contains(f, "public key"), strings.Contains(f, "recipients"), strings.Contains(f, "authorized keys"),
		strings.Contains(f, "host keys"), strings.Contains(f, "ssh public"), strings.Contains(f, "request"):
		return "public-key"
	}
	return "ciphertext"
}

// AddFinding records one at-rest or in-traffic artifact.
func (b *Builder) AddFinding(f inspect.Finding) {
	byRole := map[string]string{}
	var bits int
	for _, a := range f.Algorithms {
		r := b.Algorithm(a.Name, a.Primitive, a.PQ, a.Bits, f.Path, f.Format+": "+a.Role)
		if r != "" && byRole[a.Role] == "" {
			byRole[a.Role] = r
			if a.Role == "public key" {
				bits = a.Bits
			}
		}
	}
	props := []Property{{"pqscan:class", string(f.Class)}, {"pqscan:confidence", f.Confidence}, {"pqscan:format", f.Format}}
	if f.Count > 1 {
		props = append(props, Property{"pqscan:occurrences", fmt.Sprint(f.Count)})
	}
	ev := &Evidence{Occurrences: []Occurrence{{Location: f.Path, AdditionalContext: f.Format}}}
	name := f.Format + " · " + f.Path
	typ := materialType(f.Format)
	if typ == "certificate" {
		cp := &CertificateProperties{SignatureAlgorithmRef: byRole["signature"], CertificateFormat: "X.509"}
		for _, e := range f.Evidence {
			switch e.Label {
			case "Subject":
				cp.SubjectName = e.Value
			case "Issuer":
				cp.IssuerName = e.Value
				if e.Value == "self-signed" {
					cp.IssuerName = cp.SubjectName
				}
			case "Valid until":
				cp.NotValidAfter = dateTime(e.Value)
			}
		}
		if key := byRole["public key"]; key != "" {
			k := b.add(Component{Name: "Public key · " + f.Path, CryptoProperties: &CryptoProperties{AssetType: "related-crypto-material",
				RelatedCryptoMaterialProperties: &RelatedMaterial{Type: "public-key", AlgorithmRef: key, Size: bits}}, Evidence: ev}, "crypto/key/"+f.Path)
			cp.SubjectPublicKeyRef = k.BOMRef
		}
		b.add(Component{Name: name, Description: f.Headline, CryptoProperties: &CryptoProperties{AssetType: "certificate", CertificateProperties: cp},
			Evidence: ev, Properties: props}, "crypto/certificate/"+f.Path)
		return
	}
	rm := &RelatedMaterial{Type: typ, Size: bits}
	switch typ {
	case "private-key", "public-key":
		rm.AlgorithmRef = byRole["public key"]
		if f.Format != "" && strings.Contains(strings.ToLower(f.Format), "pkcs#12") {
			rm.Format = "PKCS#12"
		}
		if typ == "private-key" {
			switch {
			case f.Has(inspect.FlagPlainPrivateKey):
				rm.SecuredBy = &SecuredBy{Mechanism: "None"}
			case byRole["key protection"] != "":
				rm.SecuredBy = &SecuredBy{Mechanism: "Password-based encryption", AlgorithmRef: byRole["key protection"]}
			}
		}
	case "signature":
		rm.AlgorithmRef = byRole["signature"]
	default: // ciphertext, token
		rm.AlgorithmRef = orDefault(byRole["content"], byRole["signature"])
		wrap := orDefault(byRole["recipient"], byRole["key protection"])
		if f.Protection != "" || wrap != "" {
			rm.SecuredBy = &SecuredBy{Mechanism: f.Protection, AlgorithmRef: wrap}
		}
	}
	b.add(Component{Name: name, Description: f.Headline, CryptoProperties: &CryptoProperties{AssetType: "related-crypto-material", RelatedCryptoMaterialProperties: rm},
		Evidence: ev, Properties: props}, "crypto/"+typ+"/"+f.Path)
}

// AddObserve records traffic: a protocol asset per connection group, and the
// artifacts found in the application data.
func (b *Builder) AddObserve(r observe.Report) {
	b.Property("pqscan:mode", "observe")
	b.Property("pqscan:verdict", string(r.Verdict))
	b.Property("pqscan:headline", r.Headline)
	for _, g := range r.Groups {
		for _, f := range g.Findings {
			b.AddFinding(f)
		}
		if g.Class == observe.ClassPlaintext || g.KeyExchange == "" || g.KeyExchange == "—" {
			continue
		}
		loc := g.ClientIP + " → " + g.Server
		if g.ServerName != "" {
			loc += " (" + g.ServerName + ")"
		}
		ctx := g.Protocol + ": negotiated key exchange"
		var kex []string
		for _, k := range strings.Split(g.KeyExchange, " + ") {
			if r := b.Algorithm(k, "key-agree", g.Class == observe.ClassPQ, 0, loc, ctx); r != "" {
				kex = append(kex, r)
			}
		}
		pp := &ProtocolProperties{CryptoRefArray: kex}
		switch {
		case g.Protocol == "SSH":
			pp.Type, pp.Version = "ssh", "2.0"
		case g.Protocol == "IKEv2":
			pp.Type, pp.Version = "ike", "2"
			pp.IKEv2TransformTypes = &IKEv2Transforms{KE: kex}
		case g.Protocol == "WireGuard":
			pp.Type = "other"
		default: // TLS, STARTTLS variants, QUIC
			pp.Type = "tls"
			pp.Version = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(g.Version, "TLS "), "(QUIC)"))
			if g.Cipher != "" {
				suite := CipherSuite{Name: g.Cipher}
				for _, a := range suiteAlgorithms(g.Cipher) {
					if r := b.Algorithm(a, "cipher", true, 0, loc, g.Protocol+": cipher suite"); r != "" {
						suite.Algorithms = append(suite.Algorithms, r)
					}
				}
				suite.Algorithms = append(suite.Algorithms, kex...)
				pp.CipherSuites = []CipherSuite{suite}
			}
			for _, e := range g.Evidence {
				if e.Label == "Server signature" {
					if r := b.Algorithm(e.Value, "signature", strings.HasPrefix(e.Value, "mldsa"), 0, loc, g.Protocol+": server signature"); r != "" {
						pp.CryptoRefArray = append(pp.CryptoRefArray, r)
					}
				}
			}
		}
		props := []Property{{"pqscan:class", string(g.Class)}, {"pqscan:outcome", g.Outcome}, {"pqscan:connections", fmt.Sprint(g.Count)},
			{"pqscan:clientOffersPQ", fmt.Sprint(g.ClientOffersPQ)}}
		b.add(Component{Name: fmt.Sprintf("%s %s", g.Protocol, loc), Description: g.Headline,
			CryptoProperties: &CryptoProperties{AssetType: "protocol", ProtocolProperties: pp},
			Evidence:         &Evidence{Occurrences: []Occurrence{{Location: loc, AdditionalContext: fmt.Sprintf("%d %s", g.Count, plural(g.Count, "connection", "connections"))}}},
			Properties:       props}, protocolRef(g))
	}
}

// protocolRef identifies a connection group: protocol, client, server, and SNI.
func protocolRef(g observe.Connection) string {
	ref := "crypto/protocol/" + strings.ToLower(g.Protocol) + "/" + g.ClientIP + "/" + g.Server
	if g.ServerName != "" {
		ref += "/" + g.ServerName
	}
	return ref
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
