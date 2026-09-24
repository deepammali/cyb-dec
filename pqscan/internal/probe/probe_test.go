package probe

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func TestBuildKeyShareLengths(t *testing.T) {
	cases := map[uint16]int{
		GroupX25519MLKEM768:     1184 + 32, // ML-KEM-768 ek || X25519
		GroupSecP256r1MLKEM768:  65 + 1184, // P-256 || ML-KEM-768 ek
		GroupSecP384r1MLKEM1024: 97 + 1568, // P-384 || ML-KEM-1024 ek
		GroupX25519:             32,
		GroupSecP256r1:          65,
		GroupSecP384r1:          97,
	}
	for id, want := range cases {
		share, err := buildKeyShare(id)
		if err != nil {
			t.Errorf("buildKeyShare(%s): %v", GroupName(id), err)
			continue
		}
		if len(share) != want {
			t.Errorf("buildKeyShare(%s) len = %d, want %d", GroupName(id), len(share), want)
		}
	}
}

func TestBuildClientHelloParses(t *testing.T) {
	// A ClientHello we build must be a well-formed TLS record.
	rec, err := buildClientHello("example.com", GroupX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	if rec[0] != 0x16 || rec[1] != 0x03 || rec[2] != 0x01 {
		t.Fatalf("bad record header: % x", rec[:3])
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if recLen != len(rec)-5 {
		t.Fatalf("record length %d != body %d", recLen, len(rec)-5)
	}
	if rec[5] != 0x01 { // handshake type client_hello
		t.Fatalf("not a ClientHello: 0x%02x", rec[5])
	}
}

func TestParseServerResponse(t *testing.T) {
	// Synthetic ServerHello selecting X25519MLKEM768.
	sh := synthServerHello(GroupX25519MLKEM768)
	c, err := parseServerResponse(sh)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Found || c.Selected != GroupX25519MLKEM768 {
		t.Fatalf("got %+v, want selected X25519MLKEM768", c)
	}

	// An alert record means "not supported".
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28} // fatal handshake_failure
	c, err = parseServerResponse(alert)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Alert {
		t.Fatalf("expected alert, got %+v", c)
	}
}

// synthServerHello builds a minimal TLS record with a ServerHello selecting group.
func synthServerHello(group uint16) []byte {
	ks := append([]byte{}, u16(group)...) // key_share ext data: selected group ...
	ks = append(ks, u16(0)...)            // ... + zero-length key_exchange (enough to parse)
	ext := append(u16(0x0033), u16(uint16(len(ks)))...)
	ext = append(ext, ks...)

	var body []byte
	body = append(body, u16(0x0303)...)      // legacy_version
	body = append(body, make([]byte, 32)...) // random (non-HRR)
	body = append(body, 0x00)                // session_id length 0
	body = append(body, u16(0x1301)...)      // cipher_suite
	body = append(body, 0x00)                // compression
	body = append(body, u16(uint16(len(ext)))...)
	body = append(body, ext...)

	hs := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x03}
	rec = append(rec, u16(uint16(len(hs)))...)
	rec = append(rec, hs...)
	return rec
}

// TestCalibrationLive is an informational external check against a known PQC host.
// It is opt-in (needs network) and tolerant: some environments' egress does not
// carry PQC handshakes, so a negative is logged, not failed. The authoritative
// calibration is TestProbeAgainstLocalPQServer, which is hermetic.
func TestCalibrationLive(t *testing.T) {
	if os.Getenv("PQSCAN_NETTEST") == "" {
		t.Skip("set PQSCAN_NETTEST=1 to run live calibration")
	}
	ok, err := probeGroup("cloudflare.com:443", "cloudflare.com", GroupX25519MLKEM768, nil, 10*time.Second)
	if err != nil {
		t.Skipf("cannot reach cloudflare.com: %v", err)
	}
	if !ok {
		t.Skip("cloudflare.com did not negotiate X25519MLKEM768 from here " +
			"(this environment's egress may not carry PQC handshakes)")
	}
	t.Log("cloudflare.com negotiated X25519MLKEM768: external calibration OK")
}
