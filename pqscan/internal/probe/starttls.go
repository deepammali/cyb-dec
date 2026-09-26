package probe

import (
	"fmt"
	"net"
	"strings"
)

// STARTTLS preambles. Each drives a plaintext protocol up to the point where the
// server expects a TLS ClientHello, then returns the server's greeting so the
// caller can start TLS on the same connection. Reads are byte-at-a-time to avoid
// buffering past the negotiation. A server that answers but refuses the upgrade
// yields ErrNoStartTLS: its traffic on this port is plaintext.

// pgSSLRequest is PostgreSQL's SSLRequest: length=8, code 80877103.
var pgSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

// readLine reads until '\n' and returns the line without trailing CR/LF.
func readLine(conn net.Conn) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := conn.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimRight(string(b), "\r\n"), nil
			}
			b = append(b, one[0])
			if len(b) > 8192 {
				return "", fmt.Errorf("preamble line too long")
			}
		}
		if err != nil {
			return strings.TrimRight(string(b), "\r\n"), err
		}
	}
}

// readReply reads a (possibly multi-line) SMTP/FTP reply and returns its first
// line and the 3-digit code of the final line. Continuation lines have '-' as the
// 4th character; the final line has a space.
func readReply(conn net.Conn) (first, code string, err error) {
	for {
		line, err := readLine(conn)
		if err != nil {
			return first, "", err
		}
		if first == "" {
			first = line
		}
		if len(line) < 4 || line[3] != '-' {
			if len(line) >= 3 {
				return first, line[:3], nil
			}
			return first, line, nil
		}
	}
}

// SMTPStartTLS: greeting -> EHLO -> STARTTLS (ports 25/587).
func SMTPStartTLS(conn net.Conn, serverName string) (string, error) {
	greeting, code, err := readReply(conn)
	if err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(code, "22") {
		return greeting, fmt.Errorf("unexpected SMTP greeting %q", greeting)
	}
	if _, err := fmt.Fprintf(conn, "EHLO pqscan.local\r\n"); err != nil {
		return greeting, err
	}
	if _, code, err = readReply(conn); err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(code, "25") {
		return greeting, fmt.Errorf("SMTP EHLO rejected (%s)", code)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return greeting, err
	}
	if _, code, err = readReply(conn); err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(code, "22") {
		return greeting, fmt.Errorf("%w (SMTP replied %s to STARTTLS)", ErrNoStartTLS, code)
	}
	return greeting, nil
}

// IMAPStartTLS: greeting -> "a1 STARTTLS" (port 143).
func IMAPStartTLS(conn net.Conn, serverName string) (string, error) {
	greeting, err := readLine(conn)
	if err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* PREAUTH") {
		return greeting, fmt.Errorf("unexpected IMAP greeting %q", greeting)
	}
	if _, err := fmt.Fprintf(conn, "a1 STARTTLS\r\n"); err != nil {
		return greeting, err
	}
	for {
		line, err := readLine(conn)
		if err != nil {
			return greeting, err
		}
		if strings.HasPrefix(line, "a1 ") {
			if strings.HasPrefix(line, "a1 OK") {
				return greeting, nil
			}
			return greeting, fmt.Errorf("%w (IMAP replied %q)", ErrNoStartTLS, line)
		}
	}
}

// POP3StartTLS: greeting -> STLS (port 110).
func POP3StartTLS(conn net.Conn, serverName string) (string, error) {
	greeting, err := readLine(conn)
	if err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return greeting, fmt.Errorf("unexpected POP3 greeting %q", greeting)
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return greeting, err
	}
	line, err := readLine(conn)
	if err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(line, "+OK") {
		return greeting, fmt.Errorf("%w (POP3 replied %q to STLS)", ErrNoStartTLS, line)
	}
	return greeting, nil
}

// FTPStartTLS: greeting -> AUTH TLS (port 21).
func FTPStartTLS(conn net.Conn, serverName string) (string, error) {
	greeting, code, err := readReply(conn)
	if err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(code, "22") {
		return greeting, fmt.Errorf("unexpected FTP greeting %q", greeting)
	}
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return greeting, err
	}
	if _, code, err = readReply(conn); err != nil {
		return greeting, err
	}
	if !strings.HasPrefix(code, "23") {
		return greeting, fmt.Errorf("%w (FTP replied %s to AUTH TLS)", ErrNoStartTLS, code)
	}
	return greeting, nil
}

// PostgresStartTLS: send the SSLRequest and expect 'S' (port 5432).
func PostgresStartTLS(conn net.Conn, serverName string) (string, error) {
	if _, err := conn.Write(pgSSLRequest); err != nil {
		return "", err
	}
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return "", err
	}
	switch resp[0] {
	case 'S':
		return "", nil
	case 'N':
		return "", fmt.Errorf("%w (PostgreSQL declined the SSLRequest)", ErrNoStartTLS)
	default:
		return "", fmt.Errorf("not a PostgreSQL server (replied 0x%02x to SSLRequest)", resp[0])
	}
}
