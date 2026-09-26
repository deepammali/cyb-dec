package observe

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Artifacts in traffic sit inside messages, not at the start of a stream, so
// application streams are split into their messages before the at-rest
// detectors run: HTTP/1.x headers and bodies, and SMTP DATA sections.

type part struct {
	label string
	data  []byte
}

func payloadParts(data []byte) []part {
	switch {
	case isHTTP(data):
		if ps := httpParts(data); len(ps) > 0 {
			return ps
		}
	case bytes.Contains(data, []byte("\r\nDATA\r\n")) || bytes.HasPrefix(data, []byte("DATA\r\n")):
		if ps := smtpParts(data); len(ps) > 0 {
			return ps
		}
	}
	return []part{{"", data}}
}

func isHTTP(b []byte) bool {
	if bytes.HasPrefix(b, []byte("HTTP/1.")) {
		return true
	}
	for _, m := range []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// httpParts splits an HTTP/1.x stream into each message's header block and body.
func httpParts(data []byte) []part {
	var out []part
	br := bufio.NewReader(bytes.NewReader(data))
	response := bytes.HasPrefix(data, []byte("HTTP/"))
	for n := 1; n <= 1000; n++ {
		var hdr http.Header
		var body io.Reader
		var start string
		if response {
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				break
			}
			hdr, body, start = resp.Header, resp.Body, resp.Status
		} else {
			req, err := http.ReadRequest(br)
			if err != nil {
				break
			}
			hdr, body, start = req.Header, req.Body, req.Method+" "+req.URL.Path
		}
		var hb strings.Builder
		hb.WriteString(start + "\n")
		hdr.Write(&hb)
		out = append(out, part{fmt.Sprintf("message %d headers", n), []byte(hb.String())})
		if b, _ := io.ReadAll(io.LimitReader(body, 64<<20)); len(b) > 0 {
			out = append(out, part{fmt.Sprintf("message %d body", n), b})
		}
	}
	return out
}

// smtpParts extracts each message a client sent after DATA, undoing dot-stuffing.
func smtpParts(data []byte) []part {
	var out []part
	rest := data
	for n := 1; ; n++ {
		i := bytes.Index(rest, []byte("DATA\r\n"))
		if i < 0 || i > 0 && rest[i-1] != '\n' {
			break
		}
		rest = rest[i+6:]
		end := bytes.Index(rest, []byte("\r\n.\r\n"))
		if end < 0 {
			end = len(rest)
		}
		msg := bytes.ReplaceAll(rest[:end], []byte("\r\n.."), []byte("\r\n."))
		out = append(out, part{fmt.Sprintf("message %d", n), msg})
		if end == len(rest) {
			break
		}
		rest = rest[end+5:]
	}
	return out
}
