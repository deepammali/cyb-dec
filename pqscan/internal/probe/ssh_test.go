package probe

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func TestProbeSSHHermetic(t *testing.T) {
	ln := listenLocal(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-TestSSH_1.0\r\n"))
		readLine(c) // client identification string
		c.Write(kexinitPacket("mlkem768x25519-sha256,curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com"))
	})
	host, port := splitHostPort(t, ln.Addr().String())
	res := ProbeSSH("SSH", host, port, 5*time.Second)
	if !res.Reachable || !res.PQKeyExchange || res.BestPQGroup != "mlkem768x25519-sha256" {
		t.Fatalf("want reachable PQ via mlkem768x25519-sha256, got %+v", res)
	}
	if want := []string{"mlkem768x25519-sha256", "curve25519-sha256"}; !reflect.DeepEqual(res.Advertised, want) {
		t.Fatalf("advertised = %v, want %v (extension markers filtered)", res.Advertised, want)
	}
	if res.Address == "" {
		t.Fatal("address should record the tested IP:port")
	}
}
