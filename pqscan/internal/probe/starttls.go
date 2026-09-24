package probe

import (
	"fmt"
	"net"
	"strings"
)

// STARTTLS preambles. Each drives a plaintext protocol up to the point where the
// server expects a TLS ClientHello, then returns so the caller can start TLS on
// the same connection. Reads are byte-at-a-time to avoid buffering past the
// negotiation (the server sends nothing more until we send the ClientHello).

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

// readReply reads a (possibly multi-line) SMTP/FTP reply and returns the code of
// the final line. Continuation lines have '-' as the 4th character; the final
// line has a space.
func readReply(conn net.Conn) (string, error) {
	for {
		line, err := readLine(conn)
		if err != nil {
			return "", err
		}
		if len(line) < 4 || line[3] == ' ' {
			if len(line) >= 3 {
				return line[:3], nil
			}
			return line, nil
		}
	}
}

// SMTPStartTLS: greeting -> EHLO -> STARTTLS (ports 25/587).
func SMTPStartTLS(conn net.Conn, serverName string) error {
	if code, err := readReply(conn); err != nil || !strings.HasPrefix(code, "22") {
		return fmt.Errorf("smtp greeting %q: %v", code, err)
	}
	if _, err := fmt.Fprintf(conn, "EHLO pqscan.local\r\n"); err != nil {
		return err
	}
	if code, err := readReply(conn); err != nil || !strings.HasPrefix(code, "25") {
		return fmt.Errorf("smtp EHLO %q: %v", code, err)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if code, err := readReply(conn); err != nil || !strings.HasPrefix(code, "22") {
		return fmt.Errorf("smtp STARTTLS refused (%q): %v", code, err)
	}
	return nil
}

// IMAPStartTLS: greeting -> "a STARTTLS" (port 143).
func IMAPStartTLS(conn net.Conn, serverName string) error {
	if _, err := readLine(conn); err != nil { // untagged greeting (* OK ...)
		return err
	}
	if _, err := fmt.Fprintf(conn, "a1 STARTTLS\r\n"); err != nil {
		return err
	}
	for {
		line, err := readLine(conn)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "a1 ") {
			if strings.HasPrefix(line, "a1 OK") {
				return nil
			}
			return fmt.Errorf("imap STARTTLS refused: %s", line)
		}
	}
}

// POP3StartTLS: greeting -> STLS (port 110).
func POP3StartTLS(conn net.Conn, serverName string) error {
	if line, err := readLine(conn); err != nil || !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("pop3 greeting %q: %v", line, err)
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}
	if line, err := readLine(conn); err != nil || !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("pop3 STLS refused (%q): %v", line, err)
	}
	return nil
}

// FTPStartTLS: greeting -> AUTH TLS (port 21).
func FTPStartTLS(conn net.Conn, serverName string) error {
	if code, err := readReply(conn); err != nil || !strings.HasPrefix(code, "22") {
		return fmt.Errorf("ftp greeting %q: %v", code, err)
	}
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}
	if code, err := readReply(conn); err != nil || !strings.HasPrefix(code, "23") {
		return fmt.Errorf("ftp AUTH TLS refused (%q): %v", code, err)
	}
	return nil
}

// PostgresStartTLS: send the SSLRequest and expect 'S' (port 5432).
func PostgresStartTLS(conn net.Conn, serverName string) error {
	// length=8, SSLRequest code 80877103 (0x04d2162f)
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return err
	}
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return err
	}
	if resp[0] != 'S' {
		return fmt.Errorf("postgres does not offer TLS (replied %q)", resp[0])
	}
	return nil
}
