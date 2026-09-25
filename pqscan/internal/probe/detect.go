package probe

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Detect identifies the protocol listening on host:port from the server's first
// bytes, for scans of a user-supplied port. It returns one of "ssh", "smtp",
// "imap", "pop3", "ftp", "postgres", or "tls", plus the greeting line if any.
//
//	SSH-…            → ssh
//	* OK / * PREAUTH → imap
//	+OK              → pop3
//	220 …            → smtp or ftp (by greeting text, else by whether EHLO works)
//	silence          → PostgreSQL if it answers an SSLRequest with S/N, else tls
func Detect(host string, port int, timeout time.Duration) (proto, greeting string, err error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	wait := 1500 * time.Millisecond
	if timeout < wait {
		wait = timeout
	}
	conn.SetDeadline(time.Now().Add(wait))
	line, rerr := readLine(conn)
	if line == "" && rerr != nil {
		if ErrorKind(rerr) != "timeout" {
			return "", "", fmt.Errorf("server closed the connection before speaking: %w", rerr)
		}
		// The server waits for the client: implicit TLS or PostgreSQL.
		conn.SetDeadline(time.Now().Add(wait))
		if _, err := conn.Write(pgSSLRequest); err == nil {
			b := make([]byte, 1)
			if n, _ := conn.Read(b); n == 1 && (b[0] == 'S' || b[0] == 'N') {
				return "postgres", "", nil
			}
		}
		return "tls", "", nil
	}

	switch {
	case strings.HasPrefix(line, "SSH-"):
		return "ssh", line, nil
	case strings.HasPrefix(line, "* OK"), strings.HasPrefix(line, "* PREAUTH"):
		return "imap", line, nil
	case strings.HasPrefix(line, "+OK"):
		return "pop3", line, nil
	case strings.HasPrefix(line, "220"):
		up := strings.ToUpper(line)
		if strings.Contains(up, "FTP") {
			return "ftp", line, nil
		}
		if strings.Contains(up, "SMTP") {
			return "smtp", line, nil
		}
		// Ambiguous greeting: finish reading it, then SMTP accepts EHLO and FTP doesn't.
		conn.SetDeadline(time.Now().Add(timeout))
		first := line
		for len(line) >= 4 && line[3] == '-' {
			if line, err = readLine(conn); err != nil {
				return "", first, err
			}
		}
		line = first
		if _, err := fmt.Fprintf(conn, "EHLO pqscan.local\r\n"); err != nil {
			return "", line, err
		}
		if _, code, err := readReply(conn); err == nil && strings.HasPrefix(code, "25") {
			return "smtp", line, nil
		}
		return "ftp", line, nil
	}
	return "", line, fmt.Errorf("unrecognised greeting %q", truncate(line, 60))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
