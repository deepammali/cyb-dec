package observe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// capture builds a classic pcap (Ethernet/IPv4) from TCP and UDP exchanges.
type capture struct {
	buf bytes.Buffer
	ts  time.Time
}

func newCapture() *capture {
	c := &capture{ts: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], linkEthernet)
	c.buf.Write(h)
	return c
}

func (c *capture) frame(b []byte) {
	c.ts = c.ts.Add(time.Millisecond)
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, uint32(c.ts.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(c.ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(b)))
	c.buf.Write(h)
	c.buf.Write(b)
}

func ipv4(proto byte, src, dst netip.AddrPort, l4 []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	return append(append(eth, ip...), l4...)
}

func (c *capture) udp(src, dst netip.AddrPort, payload []byte) {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u, src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	c.frame(ipv4(17, src, dst, append(u, payload...)))
}

func (c *capture) tcp(src, dst netip.AddrPort, seq uint32, flags byte, payload []byte) {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t, src.Port())
	binary.BigEndian.PutUint16(t[2:], dst.Port())
	binary.BigEndian.PutUint32(t[4:], seq)
	t[12], t[13] = 5<<4, flags
	c.frame(ipv4(6, src, dst, append(t, payload...)))
}

// chunk is bytes one side sent.
type chunk struct {
	fromClient bool
	data       []byte
}

// tcpSession writes a full TCP connection: handshake, the chunks in order
// (split into 1400-byte segments), and FINs.
func (c *capture) tcpSession(client, server netip.AddrPort, chunks []chunk) {
	cseq, sseq := uint32(1000), uint32(90000)
	c.tcp(client, server, cseq, 0x02, nil)
	c.tcp(server, client, sseq, 0x12, nil)
	cseq++
	sseq++
	for _, ch := range chunks {
		for d := ch.data; len(d) > 0; {
			n := min(len(d), 1400)
			if ch.fromClient {
				c.tcp(client, server, cseq, 0x18, d[:n])
				cseq += uint32(n)
			} else {
				c.tcp(server, client, sseq, 0x18, d[:n])
				sseq += uint32(n)
			}
			d = d[n:]
		}
	}
	c.tcp(client, server, cseq, 0x11, nil)
	c.tcp(server, client, sseq, 0x11, nil)
}

func (c *capture) analyze(t *testing.T, o Options) Report {
	t.Helper()
	a := New(context.Background(), o)
	if err := a.Add(bytes.NewReader(c.buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	return a.Report()
}

// recorder wraps a connection and records what each side sent, in order.
type recorder struct {
	net.Conn
	mu     sync.Mutex
	chunks []chunk
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.chunks = append(r.chunks, chunk{true, append([]byte(nil), b...)})
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func (r *recorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.mu.Lock()
		r.chunks = append(r.chunks, chunk{false, append([]byte(nil), b[:n]...)})
		r.mu.Unlock()
	}
	return n, err
}

// tlsExchange runs a real crypto/tls handshake over loopback, with the client
// sending request and the server answering response, and returns what went
// over the wire plus the negotiated state.
func tlsExchange(t *testing.T, sc, cc *tls.Config, request, response []byte) ([]chunk, tls.ConnectionState) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(c, buf); err == nil {
			c.Write(response)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	tc := tls.Client(rec, cc)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Write(request)
	io.ReadFull(tc, make([]byte, len(response)))
	tc.Close()
	return rec.chunks, tc.ConnectionState()
}

var (
	cli = netip.MustParseAddrPort("10.0.0.5:51000")
	srv = netip.MustParseAddrPort("10.0.0.9:443")
)
