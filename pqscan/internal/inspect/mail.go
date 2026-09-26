package inspect

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// Mail: .eml files, mbox mailboxes, and Maildir files (one message each).
// Every MIME part is decoded and sent back through the detectors, so S/MIME
// (application/pkcs7-mime), PGP/MIME, and encrypted attachments are found.
// Subjects, addresses, and bodies are never reported.

// isMail reports whether b starts like an RFC 5322 message or an mbox.
func isMail(b []byte) bool {
	if bytes.HasPrefix(b, []byte("From ")) {
		return true
	}
	head := b[:min(len(b), 4096)]
	end := bytes.Index(head, []byte("\n\n"))
	if end < 0 {
		end = bytes.Index(head, []byte("\r\n\r\n"))
	}
	if end < 0 {
		return false
	}
	hdr := strings.ToLower(string(head[:end]))
	has := func(k string) bool { return strings.HasPrefix(hdr, k) || strings.Contains(hdr, "\n"+k) }
	return has("content-type:") && (has("from:") || has("received:") || has("mime-version:") || has("message-id:"))
}

func (in *Inspector) mail(path string, b []byte, depth int) {
	if !bytes.HasPrefix(b, []byte("From ")) {
		in.message(path, b, depth)
		return
	}
	// mbox: messages start at lines beginning "From " after a blank line.
	var msgs [][]byte
	start := 0
	for i := 0; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			break
		}
		next := i + j + 1
		if next < len(b) && bytes.HasPrefix(b[next:], []byte("From ")) && (next < 2 || b[next-2] == '\n') {
			msgs = append(msgs, b[start:next])
			start = next
		}
		i = next
	}
	msgs = append(msgs, b[start:])
	for n, m := range msgs {
		if in.ctx.Err() != nil {
			return
		}
		if k := bytes.IndexByte(m, '\n'); k >= 0 {
			m = m[k+1:] // drop the "From " separator line
		}
		in.message(fmt.Sprintf("%s#message %d", path, n+1), m, depth)
	}
}

func (in *Inspector) message(path string, b []byte, depth int) {
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		in.skip(path, "unreadable message: "+err.Error())
		return
	}
	in.part(path, textproto.MIMEHeader(msg.Header), msg.Body, depth, new(int))
}

// part walks one MIME entity. n numbers the leaf parts within a message.
func (in *Inspector) part(path string, h textproto.MIMEHeader, body io.Reader, depth int, n *int) {
	if depth > in.opts.MaxDepth {
		in.skip(path, "nested too deep")
		return
	}
	ct, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		ct = "text/plain"
	}
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "base64":
		body = base64.NewDecoder(base64.StdEncoding, &b64Clean{r: bufio.NewReader(body)})
	case "quoted-printable":
		body = quotedprintable.NewReader(body)
	}
	if strings.HasPrefix(ct, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			in.part(path, p.Header, p, depth+1, n)
		}
	}
	data, ok := in.readLimited(path, body)
	if !ok {
		return
	}
	if ct == "message/rfc822" {
		in.message(path+"/attached message", data, depth+1)
		return
	}
	*n++
	name := params["name"]
	if _, dp, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil && dp["filename"] != "" {
		name = dp["filename"]
	}
	label := fmt.Sprintf("%s/part %d", path, *n)
	if name != "" {
		label += " (" + name + ")"
	}
	if ct == "application/pgp-encrypted" {
		return // PGP/MIME version part; the ciphertext is the next part
	}
	in.scan(label, data, depth+1, true)
}

// b64Clean drops characters base64 decoding rejects (whitespace in mail bodies).
type b64Clean struct{ r *bufio.Reader }

func (c *b64Clean) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		b, err := c.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		p[n] = b
		n++
	}
	return n, nil
}

// decodeB64 decodes padded or unpadded standard base64, ignoring whitespace.
func decodeB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}
