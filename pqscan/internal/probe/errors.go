package probe

import (
	"errors"
	"net"
	"os"
	"syscall"
)

// ErrNoStartTLS means the server speaks the plaintext protocol but refused to
// upgrade to TLS, so its traffic on this port is unencrypted.
var ErrNoStartTLS = errors.New("server does not offer TLS on this port")

var (
	errNotTLS       = errors.New("not a TLS response")
	errClosedByPeer = errors.New("server closed the connection without a TLS response")
)

// ErrorKind classifies a probe failure so reports can tell a closed port from a
// filtered one from a protocol failure: refused, timeout, unreachable, dns,
// no_starttls, or protocol.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrNoStartTLS):
		return "no_starttls"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "protocol"
}
