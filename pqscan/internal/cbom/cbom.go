// Package cbom exports pqscan results as a Cryptography Bill of Materials in
// CycloneDX 1.6 JSON, so they merge into organization-wide inventories.
package cbom

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Version is pqscan's version, recorded as the BOM's tool.
var Version = "dev"

// BOM is a CycloneDX 1.6 document.
type BOM struct {
	Schema       string      `json:"$schema"`
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      Tools      `json:"tools"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Component struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref,omitempty"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

type Occurrence struct {
	Location          string `json:"location"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type CryptoProperties struct {
	AssetType                       string                 `json:"assetType"` // algorithm, certificate, protocol, related-crypto-material
	AlgorithmProperties             *AlgorithmProperties   `json:"algorithmProperties,omitempty"`
	CertificateProperties           *CertificateProperties `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedMaterial       `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties    `json:"protocolProperties,omitempty"`
	OID                             string                 `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive                string   `json:"primitive"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	Padding                  string   `json:"padding,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
}

type RelatedMaterial struct {
	Type         string     `json:"type"`
	AlgorithmRef string     `json:"algorithmRef,omitempty"`
	Size         int        `json:"size,omitempty"`
	Format       string     `json:"format,omitempty"`
	SecuredBy    *SecuredBy `json:"securedBy,omitempty"`
}

type SecuredBy struct {
	Mechanism    string `json:"mechanism,omitempty"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
}

type ProtocolProperties struct {
	Type                string           `json:"type"` // tls, ssh, ipsec, ike, other
	Version             string           `json:"version,omitempty"`
	CipherSuites        []CipherSuite    `json:"cipherSuites,omitempty"`
	IKEv2TransformTypes *IKEv2Transforms `json:"ikev2TransformTypes,omitempty"`
	CryptoRefArray      []string         `json:"cryptoRefArray,omitempty"`
}

type CipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type IKEv2Transforms struct {
	KE []string `json:"ke,omitempty"`
}

// Builder accumulates components from any number of pqscan reports.
type Builder struct {
	algs   map[string]*Component // bom-ref → algorithm component
	others []*Component
	refs   map[string]int // bom-ref uses, to keep refs unique
	props  []Property
}

func NewBuilder() *Builder {
	return &Builder{algs: map[string]*Component{}, refs: map[string]int{}}
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '+', r == ':', r == '@', r == '/':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func occurrence(c *Component, location, context string) {
	if location == "" {
		return
	}
	if c.Evidence == nil {
		c.Evidence = &Evidence{}
	}
	for _, o := range c.Evidence.Occurrences {
		if o.Location == location && o.AdditionalContext == context {
			return
		}
	}
	c.Evidence.Occurrences = append(c.Evidence.Occurrences, Occurrence{Location: location, AdditionalContext: context})
}

// Algorithm adds (or finds) an algorithm and records where it was seen. It
// returns the algorithm's bom-ref, or "" for an empty name.
func (b *Builder) Algorithm(name, primitiveHint string, pq bool, bits int, location, context string) string {
	if strings.TrimSpace(name) == "" || name == "—" {
		return ""
	}
	s := lookupSpec(name, primitiveHint, pq, bits)
	ref := "crypto/algorithm/" + slug(normalize(s.name))
	if s.param != "" && !strings.Contains(slug(s.name), s.param) {
		ref += "@" + s.param
	}
	c := b.algs[ref]
	if c == nil {
		ap := &AlgorithmProperties{Primitive: s.primitive, ParameterSetIdentifier: s.param, Curve: s.curve, Mode: s.mode, Padding: s.padding, CryptoFunctions: s.functions}
		if s.classical > 0 {
			v := s.classical
			ap.ClassicalSecurityLevel = &v
		}
		if s.quantum >= 0 {
			v := s.quantum
			ap.NISTQuantumSecurityLevel = &v
		}
		c = &Component{Type: "cryptographic-asset", BOMRef: ref, Name: s.name,
			CryptoProperties: &CryptoProperties{AssetType: "algorithm", AlgorithmProperties: ap, OID: s.oid}}
		if s.quantum >= 0 {
			c.Properties = append(c.Properties, Property{"pqscan:quantumSafe", fmt.Sprint(s.quantum > 0)})
		} else if pq {
			c.Properties = append(c.Properties, Property{"pqscan:quantumSafe", "true"})
		}
		b.algs[ref] = c
	}
	occurrence(c, location, context)
	return ref
}

func (b *Builder) ref(base string) string {
	base = slug(base)
	b.refs[base]++
	if n := b.refs[base]; n > 1 {
		return fmt.Sprintf("%s#%d", base, n)
	}
	return base
}

// add appends a non-algorithm component with a unique bom-ref.
func (b *Builder) add(c Component, refBase string) *Component {
	c.Type = "cryptographic-asset"
	c.BOMRef = b.ref(refBase)
	b.others = append(b.others, &c)
	return b.others[len(b.others)-1]
}

// Property records a document-level property (mode, verdict, headline).
func (b *Builder) Property(name, value string) {
	if value != "" {
		b.props = append(b.props, Property{name, value})
	}
}

func uuid4() string {
	var u [16]byte
	rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// BOM returns the document: algorithms first (by name), then everything else
// in the order it was added.
func (b *Builder) BOM() BOM {
	doc := BOM{
		Schema: "http://cyclonedx.org/schema/bom-1.6.schema.json", BOMFormat: "CycloneDX", SpecVersion: "1.6",
		SerialNumber: uuid4(), Version: 1,
		Metadata: Metadata{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Tools:      Tools{Components: []Component{{Type: "application", Name: "pqscan", Version: Version}}},
			Properties: b.props,
		},
		Components: []Component{},
	}
	var algs []*Component
	for _, c := range b.algs {
		algs = append(algs, c)
	}
	sort.Slice(algs, func(i, j int) bool { return algs[i].BOMRef < algs[j].BOMRef })
	for _, c := range algs {
		doc.Components = append(doc.Components, *c)
	}
	for _, c := range b.others {
		doc.Components = append(doc.Components, *c)
	}
	return doc
}
