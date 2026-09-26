package inspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Options bound what the inspector reads.
type Options struct {
	MaxFileSize int64 // bytes read from any one file or archive member (default 64 MiB)
	MaxDepth    int   // archive and mail nesting (default 6)
	MaxTotal    int64 // bytes read across everything, decompressed (default 4 GiB)
}

const (
	DefaultMaxFileSize = 64 << 20
	DefaultMaxDepth    = 6
	DefaultMaxTotal    = 4 << 30
	headSize           = 1 << 20 // read from files over MaxFileSize: enough for every header format
	maxSkips           = 200
)

func (o Options) withDefaults() Options {
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxTotal <= 0 {
		o.MaxTotal = DefaultMaxTotal
	}
	return o
}

// Inspector accumulates findings across files. Use it from one goroutine.
type Inspector struct {
	ctx      context.Context
	opts     Options
	emit     func(Finding)
	findings []Finding
	files    int
	bytes    int64
	skipped  []Skip
	skips    int
	roots    []string
}

// New returns an inspector; emit (optional) receives each finding as found.
func New(ctx context.Context, o Options, emit func(Finding)) *Inspector {
	return &Inspector{ctx: ctx, opts: o.withDefaults(), emit: emit}
}

func (in *Inspector) add(fs ...Finding) {
	for _, f := range fs {
		if f.Format == "" {
			continue
		}
		in.findings = append(in.findings, f)
		if in.emit != nil {
			in.emit(f)
		}
	}
}

func (in *Inspector) skip(path, reason string) {
	in.skips++
	if len(in.skipped) < maxSkips {
		in.skipped = append(in.skipped, Skip{path, reason})
	}
}

// budget reserves n bytes of the total read budget.
func (in *Inspector) budget(n int64) bool {
	if in.bytes+n > in.opts.MaxTotal {
		return false
	}
	in.bytes += n
	return true
}

// Path inspects a file or directory tree. Symbolic links are never followed,
// and only regular files are read.
func (in *Inspector) Path(root string) {
	in.roots = append(in.roots, root)
	st, err := os.Lstat(root)
	if err != nil {
		in.skip(root, err.Error())
		return
	}
	if !st.IsDir() {
		in.file(root, st)
		return
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if in.ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			in.skip(p, err.Error())
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			in.skip(p, err.Error())
			return nil
		}
		in.file(p, info)
		return nil
	})
}

func (in *Inspector) file(p string, info fs.FileInfo) {
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		in.skip(p, "symbolic link (not followed)")
		return
	case !info.Mode().IsRegular():
		in.skip(p, "not a regular file")
		return
	case info.Size() == 0:
		return
	}
	f, err := os.Open(p)
	if err != nil {
		in.skip(p, err.Error())
		return
	}
	defer f.Close()
	// ZIP archives are read in place through their central directory.
	var magic [4]byte
	if n, _ := f.ReadAt(magic[:], 0); n == 4 && isZip(magic[:]) {
		in.files++
		in.zip(p, f, info.Size(), 0)
		return
	}
	size, full := info.Size(), true
	if size > in.opts.MaxFileSize {
		size, full = headSize, false
		in.skip(p, fmt.Sprintf("larger than %d MiB: only the first 1 MiB (the headers) was read", in.opts.MaxFileSize>>20))
	}
	if !in.budget(size) {
		in.skip(p, "total read budget exhausted")
		return
	}
	data := make([]byte, size)
	n, err := io.ReadFull(f, data)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		in.skip(p, err.Error())
		return
	}
	in.scan(p, data[:n], 0, full)
}

// Bytes inspects one in-memory file (an upload), named name.
func (in *Inspector) Bytes(name string, data []byte) {
	in.roots = append(in.roots, name)
	in.bytes += int64(len(data))
	in.scan(name, data, 0, true)
}

func isZip(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 && b[3] == 4 || b[2] == 5 && b[3] == 6)
}

// scan dispatches one file's bytes to the detectors. full is false when only
// the head of a large file was read.
func (in *Inspector) scan(path string, b []byte, depth int, full bool) {
	if in.ctx.Err() != nil {
		return
	}
	in.files++
	if depth > in.opts.MaxDepth {
		in.skip(path, "nested too deep")
		return
	}
	switch {
	case isZip(b) && full:
		in.zip(path, bytes.NewReader(b), int64(len(b)), depth)
		return
	case len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b && full:
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			in.skip(path, "bad gzip: "+err.Error())
			return
		}
		in.stream(path, strings.TrimSuffix(strings.TrimSuffix(path, ".gz"), ".tgz"), zr, depth)
		return
	case bytes.HasPrefix(b, []byte("BZh")) && len(b) > 10 && bytes.Equal(b[4:10], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) && full:
		in.stream(path, strings.TrimSuffix(path, ".bz2"), bzip2.NewReader(bytes.NewReader(b)), depth)
		return
	case isTar(b) && full:
		in.tar(path, bytes.NewReader(b), depth)
		return
	}
	if f, ok := luksFinding(path, b); ok {
		in.add(f)
		return
	}
	if f, ok := kdbxFinding(path, b); ok {
		in.add(f)
		return
	}
	if f, ok := javaKeyStoreFinding(path, b); ok {
		in.add(f)
		return
	}
	if f, ok := opensslEncFinding(path, b); ok {
		in.add(f)
		return
	}
	if f, ok := ageFinding(path, b, false); ok {
		in.add(f)
		return
	}
	if len(b) > 0 && b[0] == 0x30 {
		if fs := derFindings(path, b); len(fs) > 0 {
			in.add(fs...)
			return
		}
	}
	if looksLikePGP(b) {
		if fs := pgpFindings(path, b, ""); len(fs) > 0 {
			in.add(fs...)
			return
		}
	}
	if isText(b) {
		in.text(path, b, depth)
	}
}

// derFindings tries each DER structure pqscan describes.
func derFindings(path string, b []byte) []Finding {
	n, _, err := parseNode(b)
	if err != nil || !n.isSeq() {
		return nil
	}
	if f, ok := cmsFinding(path, n); ok {
		return []Finding{f}
	}
	if f, ok := pkcs12Finding(path, n); ok {
		return []Finding{f}
	}
	if f, ok := certFinding(path, n); ok {
		return []Finding{f}
	}
	if f, ok := csrFinding(path, n.raw); ok {
		return []Finding{f}
	}
	if f, ok := derKeyFinding(path, n); ok {
		return []Finding{f}
	}
	return nil
}

func isTar(b []byte) bool {
	return len(b) >= 262 && bytes.Equal(b[257:262], []byte("ustar"))
}

// isText reports whether b looks like text: valid UTF-8-ish with no NULs early on.
func isText(b []byte) bool {
	head := b[:min(len(b), 8192)]
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	bad := 0
	for len(head) > 0 {
		r, size := utf8.DecodeRune(head)
		if r == utf8.RuneError && size == 1 {
			bad++
		}
		head = head[size:]
	}
	return bad < 8
}

// text runs the detectors for textual formats: armored blocks, mail, tokens,
// key lines, and config-embedded encryption.
func (in *Inspector) text(path string, b []byte, depth int) {
	if f, ok := ansibleFinding(path, b); ok {
		in.add(f)
		return
	}
	if isMail(b) {
		in.mail(path, b, depth)
		return
	}
	if f, ok := sopsFinding(path, b); ok {
		in.add(f)
		return
	}
	in.armor(path, b, depth)
	in.add(joseFindings(path, b)...)
	in.add(sshPublicKeyFindings(path, b)...)
	in.add(ageKeyFindings(path, b)...)
}

// armor finds every "-----BEGIN X-----" block and describes it.
func (in *Inspector) armor(path string, b []byte, depth int) {
	rest := b
	idx := 0
	for {
		i := bytes.Index(rest, []byte("-----BEGIN "))
		if i < 0 {
			return
		}
		rest = rest[i:]
		eol := bytes.Index(rest, []byte("-----\n"))
		if eol < 0 {
			eol = bytes.Index(rest, []byte("-----\r\n"))
		}
		if eol < 0 {
			return
		}
		label := string(rest[len("-----BEGIN "):eol])
		end := bytes.Index(rest, []byte("-----END "+label+"-----"))
		if end < 0 {
			return
		}
		block := rest[:end+len("-----END "+label+"-----")]
		rest = rest[len(block):]
		idx++
		where := path
		if idx > 1 || len(bytes.TrimSpace(b)) != len(bytes.TrimSpace(block)) {
			where = fmt.Sprintf("%s#block %d", path, idx)
		}
		in.add(armorFindings(where, label, block)...)
	}
}

func armorFindings(path, label string, block []byte) []Finding {
	if strings.HasPrefix(label, "PGP ") {
		if label == "PGP SIGNED MESSAGE" {
			return nil // the signature follows in its own block
		}
		data := dearmorPGP(block)
		if data == nil {
			return nil
		}
		return pgpFindings(path, data, label)
	}
	p, _ := pem.Decode(block)
	if p == nil {
		return nil
	}
	switch label {
	case "AGE ENCRYPTED FILE":
		if f, ok := ageFinding(path, p.Bytes, true); ok {
			return []Finding{f}
		}
	case "OPENSSH PRIVATE KEY":
		if f, ok := opensshKeyFinding(path, p.Bytes); ok {
			return []Finding{f}
		}
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
		if f, ok := legacyPEMFinding(path, p); ok {
			return []Finding{f}
		}
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		if f, ok := csrFinding(path, p.Bytes); ok {
			return []Finding{f}
		}
	default:
		return derFindings(path, p.Bytes)
	}
	return nil
}

// dearmorPGP decodes an ASCII-armored OpenPGP block (RFC 9580 §6), dropping
// the armor headers and the optional CRC-24 line.
func dearmorPGP(block []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(block), "\r\n", "\n"), "\n")
	var body strings.Builder
	inHeaders := true
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "-----END"):
			data, err := decodeB64(body.String())
			if err != nil {
				return nil
			}
			return data
		case inHeaders && strings.Contains(l, ": "):
			continue
		case inHeaders && l == "":
			inHeaders = false
		case strings.HasPrefix(l, "=") && len(l) == 5:
			continue // CRC-24
		default:
			inHeaders = false
			body.WriteString(l)
		}
	}
	return nil
}

// zip reads the central directory: encryption per entry, then each plain member.
func (in *Inspector) zip(path string, r io.ReaderAt, size int64, depth int) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		in.skip(path, "bad ZIP: "+err.Error())
		return
	}
	enc := zipEnc{aes: map[int]int{}}
	for _, f := range zr.File {
		if in.ctx.Err() != nil {
			return
		}
		member := path + "!" + f.Name
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&0x1 != 0 {
			switch {
			case f.Method == 99:
				enc.aes[zipAESBits(f.Extra)]++
			case f.Flags&0x40 != 0:
				enc.strong++
			default:
				enc.zipCryp++
			}
			continue
		}
		if f.Mode()&fs.ModeSymlink != 0 {
			in.skip(member, "symbolic link (not followed)")
			continue
		}
		if int64(f.UncompressedSize64) > in.opts.MaxFileSize {
			in.skip(member, "member larger than the per-file limit")
			continue
		}
		rc, err := f.Open()
		if err != nil {
			in.skip(member, err.Error())
			continue
		}
		data, ok := in.readLimited(member, rc)
		rc.Close()
		if ok {
			in.scan(member, data, depth+1, true)
		}
	}
	if f, ok := enc.finding(path); ok {
		in.add(f)
	}
}

// zipAESBits reads the WinZip AES extra field (0x9901): strength 1/2/3 = 128/192/256.
func zipAESBits(extra []byte) int {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		l := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+l > len(extra) {
			break
		}
		if id == 0x9901 && l >= 7 {
			return map[byte]int{1: 128, 2: 192, 3: 256}[extra[4+4]]
		}
		extra = extra[4+l:]
	}
	return 0
}

// readLimited reads a member, refusing more than MaxFileSize (zip bombs) or the total budget.
func (in *Inspector) readLimited(path string, r io.Reader) ([]byte, bool) {
	data, err := io.ReadAll(io.LimitReader(r, in.opts.MaxFileSize+1))
	if err != nil {
		in.skip(path, err.Error())
		return nil, false
	}
	if int64(len(data)) > in.opts.MaxFileSize {
		in.skip(path, "expands beyond the per-file limit")
		return nil, false
	}
	if !in.budget(int64(len(data))) {
		in.skip(path, "total read budget exhausted")
		return nil, false
	}
	return data, true
}

// stream handles a decompressed stream: a tar archive or a single file.
func (in *Inspector) stream(path, inner string, r io.Reader, depth int) {
	data, ok := in.readLimited(path, r)
	if !ok {
		return
	}
	if isTar(data) {
		in.tar(path, bytes.NewReader(data), depth)
		return
	}
	in.scan(inner, data, depth+1, true)
}

func (in *Inspector) tar(path string, r io.Reader, depth int) {
	tr := tar.NewReader(r)
	for {
		if in.ctx.Err() != nil {
			return
		}
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			in.skip(path, "bad tar: "+err.Error())
			return
		}
		member := path + "!" + h.Name
		switch h.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			in.skip(member, "link (not followed)")
			continue
		default:
			continue
		}
		if h.Size > in.opts.MaxFileSize {
			in.skip(member, "member larger than the per-file limit")
			continue
		}
		if data, ok := in.readLimited(member, tr); ok {
			in.scan(member, data, depth+1, true)
		}
	}
}
