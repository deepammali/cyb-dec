package observe

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type endpoint struct {
	addr netip.Addr
	port uint16
}

func (e endpoint) String() string { return netip.AddrPortFrom(e.addr, e.port).String() }

func less(a, b endpoint) bool {
	if c := a.addr.Compare(b.addr); c != 0 {
		return c < 0
	}
	return a.port < b.port
}

type flowKey struct {
	proto uint8
	a, b  endpoint // a < b
}

func keyOf(p packet) (flowKey, endpoint) {
	s, d := endpoint{p.src, p.sport}, endpoint{p.dst, p.dport}
	if less(d, s) {
		s, d = d, s
	}
	return flowKey{p.proto, s, d}, endpoint{p.src, p.sport}
}

// stream reassembles one direction of a TCP connection.
type stream struct {
	base      uint32
	haveBase  bool
	data      []byte
	pending   map[uint32][]byte // relative offset → segment, not yet contiguous
	truncated bool              // hit the cap
	gap       bool              // a missing segment stopped assembly
	limit     int
}

func (s *stream) add(seq uint32, syn bool, payload []byte) {
	if syn {
		s.base, s.haveBase = seq+1, true
		return
	}
	if len(payload) == 0 {
		return
	}
	if !s.haveBase {
		s.base, s.haveBase = seq, true // capture started mid-connection
	}
	off := seq - s.base
	if off > 1<<30 { // before the base: a retransmission of something already past
		return
	}
	if int(off) >= s.limit {
		s.truncated = true
		return
	}
	if s.pending == nil {
		s.pending = map[uint32][]byte{}
	}
	if old, ok := s.pending[off]; !ok || len(old) < len(payload) {
		s.pending[off] = append([]byte(nil), payload...)
	}
	s.assemble()
}

func (s *stream) assemble() {
	for progress := true; progress; {
		progress = false
		next := uint32(len(s.data))
		for off, seg := range s.pending {
			end := off + uint32(len(seg))
			switch {
			case end <= next:
				delete(s.pending, off) // retransmitted data we already have
			case off <= next:
				s.data = append(s.data, seg[next-off:]...)
				delete(s.pending, off)
				progress = true
			}
			if progress {
				break
			}
		}
	}
	if len(s.data) > s.limit {
		s.data, s.truncated = s.data[:s.limit], true
	}
}

// finish reports whether a gap (a segment the capture missed) remains.
func (s *stream) finish() {
	if len(s.pending) > 0 {
		s.gap = true
	}
}

const maxDatagrams = 64

// flow is one TCP connection or UDP association.
type flow struct {
	key         flowKey
	proto       uint8
	client      endpoint
	sawSYN      bool
	first, last time.Time
	packets     int
	bytes       int64
	streams     map[endpoint]*stream  // TCP: keyed by sender
	datagrams   map[endpoint][][]byte // UDP: first datagrams per sender
	order       []endpoint            // senders in order of first appearance
}

func (f *flow) sender(e endpoint) {
	for _, o := range f.order {
		if o == e {
			return
		}
	}
	f.order = append(f.order, e)
}

// other returns the peer of e in this flow.
func (f *flow) other(e endpoint) endpoint {
	if e == f.key.a {
		return f.key.b
	}
	return f.key.a
}

func (f *flow) String() string {
	return fmt.Sprintf("%s %s ↔ %s", map[uint8]string{6: "tcp", 17: "udp"}[f.proto], f.key.a, f.key.b)
}

// table holds every flow in a capture.
type table struct {
	flows     map[flowKey]*flow
	streamCap int
}

func newTable(streamCap int) *table {
	return &table{flows: map[flowKey]*flow{}, streamCap: streamCap}
}

func (t *table) add(p packet) {
	k, from := keyOf(p)
	f := t.flows[k]
	if f == nil {
		f = &flow{key: k, proto: p.proto, first: p.ts, client: from}
		t.flows[k] = f
	}
	f.last = p.ts
	f.packets++
	f.bytes += int64(len(p.payload))
	f.sender(from)
	switch p.proto {
	case 6:
		if p.syn && !p.ack && !f.sawSYN {
			f.client, f.sawSYN = from, true
		} else if p.syn && p.ack && !f.sawSYN {
			f.client, f.sawSYN = f.other(from), true
		}
		if f.streams == nil {
			f.streams = map[endpoint]*stream{}
		}
		s := f.streams[from]
		if s == nil {
			s = &stream{limit: t.streamCap}
			f.streams[from] = s
		}
		s.add(p.seq, p.syn, p.payload)
	case 17:
		if f.datagrams == nil {
			f.datagrams = map[endpoint][][]byte{}
		}
		if len(f.datagrams[from]) < maxDatagrams {
			f.datagrams[from] = append(f.datagrams[from], append([]byte(nil), p.payload...))
		}
	}
}

// sorted returns flows in order of first packet.
func (t *table) sorted() []*flow {
	out := make([]*flow, 0, len(t.flows))
	for _, f := range t.flows {
		for _, s := range f.streams {
			s.finish()
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].first.Equal(out[j].first) {
			return out[i].first.Before(out[j].first)
		}
		return less(out[i].key.a, out[j].key.a)
	})
	return out
}

// directions returns (client→server bytes, server→client bytes, server endpoint).
func (f *flow) directions() ([]byte, []byte, endpoint) {
	server := f.other(f.client)
	var c, s []byte
	if st := f.streams[f.client]; st != nil {
		c = st.data
	}
	if st := f.streams[server]; st != nil {
		s = st.data
	}
	return c, s, server
}
