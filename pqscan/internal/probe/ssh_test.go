package probe

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildKEXINIT builds an SSH_MSG_KEXINIT binary packet whose first name-list
// (kex_algorithms) is kexAlgs. Only the first name-list matters to the parser.
func buildKEXINIT(kexAlgs string) []byte {
	nameList := func(s string) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(s)))
		return append(b, []byte(s)...)
	}
	var payload []byte
	payload = append(payload, 20)                         // SSH_MSG_KEXINIT
	payload = append(payload, make([]byte, 16)...)        // cookie
	payload = append(payload, nameList(kexAlgs)...)       // kex_algorithms
	payload = append(payload, nameList("ssh-ed25519")...) // server_host_key_algorithms
	// (remaining name-lists omitted; parser stops after kex_algorithms)

	base := 4 + 1 + len(payload)
	padLen := 8 - (base % 8)
	if padLen < 4 {
		padLen += 8
	}
	pktLen := 1 + len(payload) + padLen
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(pktLen))
	out = append(out, byte(padLen))
	out = append(out, payload...)
	out = append(out, make([]byte, padLen)...)
	return out
}

func TestProbeSSHHermetic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("SSH-2.0-TestSSH_1.0\r\n"))
		readLine(c) // client identification string
		c.Write(buildKEXINIT("mlkem768x25519-sha256,curve25519-sha256,ecdh-sha2-nistp256"))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	res := ProbeSSH("SSH", host, atoiPort(portStr), 5*time.Second)
	if !res.Reachable {
		t.Fatalf("expected reachable, err=%s", res.Error)
	}
	if !res.PQKeyExchange {
		t.Fatalf("expected PQ kex detected; groups=%+v", res.Groups)
	}
	var mlkem bool
	for _, g := range res.Groups {
		if g.Group == "mlkem768x25519-sha256" && g.Supported {
			mlkem = true
		}
	}
	if !mlkem {
		t.Fatalf("expected mlkem768x25519-sha256 supported; groups=%+v", res.Groups)
	}
}

func atoiPort(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}
