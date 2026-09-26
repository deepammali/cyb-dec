// Package observe analyzes captured traffic (pcap, pcapng) for how each
// connection establishes its keys: TLS (TCP and QUIC), SSH, IKEv2, and
// WireGuard handshakes, plaintext application data, and, with a key log you
// provide, the application data inside TLS 1.3.
package observe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// packet is one decoded TCP or UDP packet.
type packet struct {
	ts            time.Time
	src, dst      netip.Addr
	sport, dport  uint16
	proto         uint8 // 6 TCP, 17 UDP
	seq           uint32
	syn, fin, rst bool
	ack           bool
	payload       []byte
}

// Link-layer types (tcpdump.org/linktypes.html).
const (
	linkNull     = 0
	linkEthernet = 1
	linkRaw      = 101
	linkLoop     = 108
	linkSLL      = 113
	linkIPv4     = 228
	linkIPv6     = 229
	linkSLL2     = 276
)

var errFormat = errors.New("not a pcap or pcapng capture")

// reader yields raw frames with their link type and timestamp.
type reader interface {
	next() (frame []byte, link int, ts time.Time, err error)
}

func newReader(r io.Reader) (reader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, errFormat
	}
	switch binary.LittleEndian.Uint32(magic) {
	case 0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1:
		return newPcap(br)
	case 0x0a0d0d0a:
		return &pcapng{r: br}, nil
	}
	return nil, errFormat
}

// Classic pcap.
type pcap struct {
	r     *bufio.Reader
	order binary.ByteOrder
	nano  bool
	link  int
}

func newPcap(r *bufio.Reader) (*pcap, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, errFormat
	}
	p := &pcap{r: r}
	switch m := binary.LittleEndian.Uint32(hdr); m {
	case 0xa1b2c3d4, 0xa1b23c4d:
		p.order, p.nano = binary.LittleEndian, m == 0xa1b23c4d
	default:
		p.order, p.nano = binary.BigEndian, m == 0x4d3cb2a1
	}
	p.link = int(p.order.Uint32(hdr[20:]) & 0x0fffffff)
	return p, nil
}

// eof treats a capture cut off mid-record as its end; other errors (a failed
// upload, a read error) are returned.
func eof(err error) error {
	if err == io.ErrUnexpectedEOF {
		return io.EOF
	}
	return err
}

func (p *pcap) next() ([]byte, int, time.Time, error) {
	var h [16]byte
	if _, err := io.ReadFull(p.r, h[:]); err != nil {
		return nil, 0, time.Time{}, eof(err)
	}
	sec, frac := int64(p.order.Uint32(h[0:])), int64(p.order.Uint32(h[4:]))
	incl := int(p.order.Uint32(h[8:]))
	if incl > 1<<24 {
		return nil, 0, time.Time{}, fmt.Errorf("pcap record of %d bytes: corrupt capture", incl)
	}
	buf := make([]byte, incl)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return nil, 0, time.Time{}, eof(err)
	}
	if !p.nano {
		frac *= 1000
	}
	return buf, p.link, time.Unix(sec, frac).UTC(), nil
}

// pcapng (draft-ietf-opsawg-pcapng): section, interface, and packet blocks.
type pcapng struct {
	r     *bufio.Reader
	order binary.ByteOrder
	links []int
	tsres []float64 // seconds per timestamp unit, per interface
}

func (p *pcapng) next() ([]byte, int, time.Time, error) {
	for {
		var h [8]byte
		if _, err := io.ReadFull(p.r, h[:]); err != nil {
			return nil, 0, time.Time{}, eof(err)
		}
		typ := binary.LittleEndian.Uint32(h[:])
		if typ == 0x0a0d0d0a { // section header: learn the byte order
			var bom [4]byte
			if _, err := io.ReadFull(p.r, bom[:]); err != nil {
				return nil, 0, time.Time{}, eof(err)
			}
			if binary.LittleEndian.Uint32(bom[:]) == 0x1a2b3c4d {
				p.order = binary.LittleEndian
			} else {
				p.order = binary.BigEndian
			}
			total := int(p.order.Uint32(h[4:]))
			if total < 12 || total > 1<<24 {
				return nil, 0, time.Time{}, errFormat
			}
			if _, err := p.r.Discard(total - 12); err != nil {
				return nil, 0, time.Time{}, eof(err)
			}
			p.links, p.tsres = nil, nil
			continue
		}
		if p.order == nil {
			return nil, 0, time.Time{}, errFormat
		}
		typ = p.order.Uint32(h[:])
		total := int(p.order.Uint32(h[4:]))
		if total < 12 || total > 1<<24 {
			return nil, 0, time.Time{}, fmt.Errorf("pcapng block of %d bytes: corrupt capture", total)
		}
		body := make([]byte, total-8)
		if _, err := io.ReadFull(p.r, body); err != nil {
			return nil, 0, time.Time{}, eof(err)
		}
		body = body[:len(body)-4] // trailing length
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				continue
			}
			p.links = append(p.links, int(p.order.Uint16(body)))
			res := 1e-6
			for opts := body[8:]; len(opts) >= 4; {
				code, l := p.order.Uint16(opts), int(p.order.Uint16(opts[2:]))
				if code == 0 || 4+l > len(opts) {
					break
				}
				if code == 9 && l >= 1 { // if_tsresol
					v := opts[4]
					if v&0x80 == 0 {
						res = pow(10, -int(v))
					} else {
						res = pow(2, -int(v&0x7f))
					}
				}
				opts = opts[4+(l+3)&^3:]
			}
			p.tsres = append(p.tsres, res)
		case 6: // enhanced packet
			if len(body) < 20 {
				continue
			}
			iface := int(p.order.Uint32(body))
			ts := uint64(p.order.Uint32(body[4:]))<<32 | uint64(p.order.Uint32(body[8:]))
			capLen := int(p.order.Uint32(body[12:]))
			if iface >= len(p.links) || 20+capLen > len(body) {
				continue
			}
			secs := float64(ts) * p.tsres[iface]
			return body[20 : 20+capLen], p.links[iface], time.Unix(0, int64(secs*1e9)).UTC(), nil
		case 3: // simple packet
			if len(body) < 4 || len(p.links) == 0 {
				continue
			}
			return body[4:], p.links[0], time.Time{}, nil
		}
	}
}

func pow(b float64, e int) float64 {
	r := 1.0
	for i := 0; i < -e; i++ {
		r /= b
	}
	return r
}

// decode turns a frame into a TCP or UDP packet; ok is false for anything else.
func decode(frame []byte, link int, ts time.Time) (packet, bool) {
	var l3 []byte
	var ethType uint16
	switch link {
	case linkEthernet:
		if len(frame) < 14 {
			return packet{}, false
		}
		ethType, l3 = binary.BigEndian.Uint16(frame[12:]), frame[14:]
		for (ethType == 0x8100 || ethType == 0x88a8) && len(l3) >= 4 { // VLAN tags
			ethType, l3 = binary.BigEndian.Uint16(l3[2:]), l3[4:]
		}
	case linkSLL:
		if len(frame) < 16 {
			return packet{}, false
		}
		ethType, l3 = binary.BigEndian.Uint16(frame[14:]), frame[16:]
	case linkSLL2:
		if len(frame) < 20 {
			return packet{}, false
		}
		ethType, l3 = binary.BigEndian.Uint16(frame[0:]), frame[20:]
	case linkNull, linkLoop:
		if len(frame) < 4 {
			return packet{}, false
		}
		l3 = frame[4:]
	case linkRaw, linkIPv4, linkIPv6:
		l3 = frame
	default:
		return packet{}, false
	}
	if len(l3) == 0 {
		return packet{}, false
	}
	switch {
	case ethType == 0x0800 || ethType == 0 && l3[0]>>4 == 4:
		return decodeIPv4(l3, ts)
	case ethType == 0x86dd || ethType == 0 && l3[0]>>4 == 6:
		return decodeIPv6(l3, ts)
	}
	return packet{}, false
}

func decodeIPv4(b []byte, ts time.Time) (packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || total < ihl || len(b) < ihl {
		return packet{}, false
	}
	if total < len(b) {
		b = b[:total] // drop Ethernet padding
	}
	if frag := binary.BigEndian.Uint16(b[6:]); frag&0x1fff != 0 || frag&0x2000 != 0 {
		return packet{}, false // fragments: handshakes don't fragment at the IP layer in practice
	}
	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])
	return decodeL4(b[9], b[ihl:], src, dst, ts)
}

func decodeIPv6(b []byte, ts time.Time) (packet, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return packet{}, false
	}
	plen := int(binary.BigEndian.Uint16(b[4:]))
	next := b[6]
	src, _ := netip.AddrFromSlice(b[8:24])
	dst, _ := netip.AddrFromSlice(b[24:40])
	rest := b[40:]
	if plen < len(rest) {
		rest = rest[:plen]
	}
	for i := 0; i < 8; i++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return packet{}, false
			}
			l := (int(rest[1]) + 1) * 8
			if l > len(rest) {
				return packet{}, false
			}
			next, rest = rest[0], rest[l:]
		case 44: // fragment
			return packet{}, false
		default:
			return decodeL4(next, rest, src, dst, ts)
		}
	}
	return packet{}, false
}

func decodeL4(proto uint8, b []byte, src, dst netip.Addr, ts time.Time) (packet, bool) {
	p := packet{ts: ts, src: src.Unmap(), dst: dst.Unmap(), proto: proto}
	switch proto {
	case 6:
		if len(b) < 20 {
			return packet{}, false
		}
		off := int(b[12]>>4) * 4
		if off < 20 || off > len(b) {
			return packet{}, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
		p.seq = binary.BigEndian.Uint32(b[4:])
		fl := b[13]
		p.fin, p.syn, p.rst, p.ack = fl&0x01 != 0, fl&0x02 != 0, fl&0x04 != 0, fl&0x10 != 0
		p.payload = b[off:]
	case 17:
		if len(b) < 8 {
			return packet{}, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
		l := int(binary.BigEndian.Uint16(b[4:]))
		if l >= 8 && l <= len(b) {
			b = b[:l]
		}
		p.payload = b[8:]
	default:
		return packet{}, false
	}
	return p, true
}
