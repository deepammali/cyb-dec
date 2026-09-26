package inspect

import (
	"encoding/asn1"
	"errors"
)

// node is one DER TLV. Headers are what matter here, so a node may be
// truncated: its declared length runs past the bytes we read, and children
// that fit are still readable.
type node struct {
	class, tag int
	compound   bool
	body       []byte // content octets we have (may be short of the declared length)
	raw        []byte // header and content octets
	truncated  bool
}

var errDER = errors.New("not DER")

// parseNode reads one TLV from b and returns it with the bytes after it.
func parseNode(b []byte) (node, []byte, error) {
	if len(b) < 2 {
		return node{}, nil, errDER
	}
	n := node{class: int(b[0] >> 6), compound: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	p := 1
	if n.tag == 0x1f { // high tag number form
		n.tag = 0
		for {
			if p >= len(b) || p > 4 {
				return node{}, nil, errDER
			}
			c := b[p]
			p++
			n.tag = n.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if p >= len(b) {
		return node{}, nil, errDER
	}
	l := int(b[p])
	p++
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || k > 4 || p+k > len(b) {
			return node{}, nil, errDER // indefinite lengths are BER, not DER
		}
		l = 0
		for _, c := range b[p : p+k] {
			l = l<<8 | int(c)
		}
		p += k
		if l < 0 {
			return node{}, nil, errDER
		}
	}
	if p+l > len(b) {
		n.body, n.raw, n.truncated = b[p:], b, true
		return n, nil, nil
	}
	n.body, n.raw = b[p:p+l], b[:p+l]
	return n, b[p+l:], nil
}

// children parses the TLVs inside a constructed node, stopping at the first
// truncated one (which is included).
func (n node) children() []node {
	var out []node
	rest := n.body
	for len(rest) > 0 {
		c, r, err := parseNode(rest)
		if err != nil {
			break
		}
		out = append(out, c)
		if c.truncated {
			break
		}
		rest = r
	}
	return out
}

func (n node) is(class, tag int) bool { return n.class == class && n.tag == tag }

const (
	classUniversal = 0
	classContext   = 2
	tagInteger     = 2
	tagOctetString = 4
	tagOID         = 6
	tagSequence    = 16
	tagSet         = 17
)

func (n node) isSeq() bool { return n.is(classUniversal, tagSequence) && n.compound }

// oid decodes an OBJECT IDENTIFIER node to dotted form.
func (n node) oid() string {
	if !n.is(classUniversal, tagOID) || n.truncated || len(n.body) == 0 || len(n.body) > 64 {
		return ""
	}
	var id asn1.ObjectIdentifier
	raw := append([]byte{0x06, byte(len(n.body))}, n.body...)
	if _, err := asn1.Unmarshal(raw, &id); err != nil {
		return ""
	}
	return id.String()
}

// algorithm reads an AlgorithmIdentifier: SEQUENCE { OID, params OPTIONAL }.
func (n node) algorithm() (oid string, params []node) {
	if !n.isSeq() {
		return "", nil
	}
	c := n.children()
	if len(c) == 0 {
		return "", nil
	}
	return c[0].oid(), c[1:]
}

// oidBytes decodes the content octets of an OID (as OpenPGP stores curve OIDs).
func oidBytes(b []byte) string {
	return node{class: classUniversal, tag: tagOID, body: b}.oid()
}
