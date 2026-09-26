package probe

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// KnownSSHPQKex are the post-quantum SSH key-exchange method names we report on.
var KnownSSHPQKex = []string{
	"mlkem768x25519-sha256",              // draft-ietf-sshm-mlkem-hybrid-kex; OpenSSH 9.9+
	"sntrup761x25519-sha512",             // OpenSSH default 9.x
	"sntrup761x25519-sha512@openssh.com", // OpenSSH vendor name
}

// IsSSHPQKex reports whether an SSH key-exchange method name is post-quantum.
func IsSSHPQKex(name string) bool { return isSSHPQKex(name) }

// IsSSHPseudoKex reports extension markers listed among key-exchange methods.
func IsSSHPseudoKex(name string) bool { return isSSHPseudoKex(name) }

func isSSHPQKex(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "mlkem") || strings.Contains(n, "sntrup") || strings.Contains(n, "kyber")
}

// isSSHPseudoKex reports extension markers that ride in kex_algorithms but are
// not key-exchange methods (RFC 8308 ext-info, OpenSSH strict-kex).
func isSSHPseudoKex(name string) bool {
	return strings.HasPrefix(name, "ext-info-") || strings.HasPrefix(name, "kex-strict-")
}

// ProbeSSH connects to an SSH server, reads its (cleartext) KEXINIT, and reports
// which post-quantum key-exchange methods it advertises. SSH publishes its
// kex_algorithms list before any encryption, so no handshake completion is needed.
func ProbeSSH(service, host string, port int, timeout time.Duration) ServiceResult {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := ServiceResult{Service: service, Kind: "ssh", Protocol: "ssh", Host: host, Port: port}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return res.fail(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	res.Address = conn.RemoteAddr().String()

	banner, err := readSSHBanner(conn)
	if err != nil {
		return res.fail(fmt.Errorf("reading SSH banner: %w", err))
	}
	res.Reachable = true
	res.Banner = banner

	if _, err := conn.Write([]byte("SSH-2.0-pqscan_0.1\r\n")); err != nil {
		return res.fail(err)
	}

	kex, err := readSSHKexAlgorithms(conn)
	if err != nil {
		return res.fail(fmt.Errorf("reading KEXINIT: %w", err))
	}

	offered := map[string]bool{}
	for _, k := range kex {
		offered[k] = true
		if !isSSHPseudoKex(k) {
			res.Advertised = append(res.Advertised, k)
		}
	}
	// Known PQC kex as a matrix.
	seen := map[string]bool{}
	for _, k := range KnownSSHPQKex {
		gr := GroupResult{Group: k, Supported: offered[k]}
		res.Groups = append(res.Groups, gr)
		seen[k] = true
		if offered[k] {
			res.PQKeyExchange = true
			if res.BestPQGroup == "" {
				res.BestPQGroup = k
			}
		}
	}
	// Any other advertised PQC kex not in the known set.
	for _, k := range kex {
		if !seen[k] && isSSHPQKex(k) {
			res.Groups = append(res.Groups, GroupResult{Group: k, Supported: true})
			res.PQKeyExchange = true
			if res.BestPQGroup == "" {
				res.BestPQGroup = k
			}
		}
	}
	return res
}

// readSSHBanner reads identification lines until one starts with "SSH-".
func readSSHBanner(conn net.Conn) (string, error) {
	for i := 0; i < 50; i++ {
		line, err := readLine(conn)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
	}
	return "", fmt.Errorf("no SSH identification string")
}

// readSSHKexAlgorithms reads one binary packet, expects SSH_MSG_KEXINIT (20), and
// returns the kex_algorithms name-list.
func readSSHKexAlgorithms(conn net.Conn) ([]string, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen < 1+16+4 || pktLen > 256*1024 {
		return nil, fmt.Errorf("implausible packet length %d", pktLen)
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	padLen := int(pkt[0])
	if 1+padLen > len(pkt) {
		return nil, fmt.Errorf("bad padding length")
	}
	payload := pkt[1 : len(pkt)-padLen]
	if len(payload) < 1+16+4 || payload[0] != 20 { // SSH_MSG_KEXINIT
		return nil, fmt.Errorf("not a KEXINIT (msg=%d)", payload[0])
	}
	p := 1 + 16 // skip message code + 16-byte cookie
	nameListLen := int(binary.BigEndian.Uint32(payload[p : p+4]))
	p += 4
	if p+nameListLen > len(payload) {
		return nil, fmt.Errorf("kex name-list overruns payload")
	}
	list := string(payload[p : p+nameListLen])
	if list == "" {
		return nil, nil
	}
	return strings.Split(list, ","), nil
}
