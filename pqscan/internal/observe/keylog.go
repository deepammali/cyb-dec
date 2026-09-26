package observe

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
)

// KeyLog holds TLS secrets in the NSS key log format (SSLKEYLOGFILE), as
// written by browsers, curl, OpenSSL, Go (tls.Config.KeyLogWriter), and most
// proxies. Only sessions whose secrets you logged can be decrypted.
type KeyLog struct {
	secrets map[string]map[string][]byte // client random (hex) → label → secret
	TLS12   int                          // CLIENT_RANDOM lines (TLS 1.2), which this version doesn't use
}

// ParseKeyLog reads a key log file.
func ParseKeyLog(r io.Reader) (*KeyLog, error) {
	k := &KeyLog{secrets: map[string]map[string][]byte{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	n := 0
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		cr := strings.ToLower(f[1])
		secret, err := hex.DecodeString(f[2])
		if err != nil || len(cr) != 64 {
			continue
		}
		if f[0] == "CLIENT_RANDOM" {
			k.TLS12++
			continue
		}
		if k.secrets[cr] == nil {
			k.secrets[cr] = map[string][]byte{}
		}
		k.secrets[cr][f[0]] = secret
		n++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n == 0 && k.TLS12 == 0 {
		return nil, errors.New("no TLS secrets found: expected SSLKEYLOGFILE lines such as CLIENT_TRAFFIC_SECRET_0")
	}
	return k, nil
}

// Sessions is the number of TLS 1.3 sessions with secrets.
func (k *KeyLog) Sessions() int {
	if k == nil {
		return 0
	}
	return len(k.secrets)
}

func (k *KeyLog) get(random []byte, label string) []byte {
	if k == nil {
		return nil
	}
	return k.secrets[hex.EncodeToString(random)][label]
}

// hkdfExpandLabel is HKDF-Expand-Label from RFC 8446 §7.1.
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(h, secret, string(info), length)
	if err != nil {
		panic(err) // lengths here are always valid
	}
	return out
}

type suite13 struct {
	keyLen int
	hash   func() hash.Hash
	aead   func(key []byte) (cipher.AEAD, error)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// suites13 lists the TLS 1.3 suites this build decrypts. ChaCha20-Poly1305 needs
// golang.org/x/crypto, which isn't in this build.
var suites13 = map[uint16]suite13{
	0x1301: {16, sha256.New, aesGCM},    // TLS_AES_128_GCM_SHA256
	0x1302: {32, sha512.New384, aesGCM}, // TLS_AES_256_GCM_SHA384
}

type trafficKeys struct {
	s      suite13
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
}

func newTrafficKeys(s suite13, secret []byte) (*trafficKeys, error) {
	key := hkdfExpandLabel(s.hash, secret, "key", nil, s.keyLen)
	a, err := s.aead(key)
	if err != nil {
		return nil, err
	}
	return &trafficKeys{s: s, secret: secret, aead: a, iv: hkdfExpandLabel(s.hash, secret, "iv", nil, 12)}, nil
}

func (k *trafficKeys) open(r record) ([]byte, byte, error) {
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(k.seq >> (8 * i))
	}
	pt, err := k.aead.Open(nil, nonce, r.data, r.hdr)
	if err != nil {
		return nil, 0, err
	}
	k.seq++
	i := len(pt) - 1
	for i >= 0 && pt[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, errors.New("empty inner plaintext")
	}
	return pt[:i], pt[i], nil
}

func (k *trafficKeys) update() (*trafficKeys, error) {
	return newTrafficKeys(k.s, hkdfExpandLabel(k.s.hash, k.secret, "traffic upd", nil, k.s.hash().Size()))
}

// decrypted is one direction of a TLS 1.3 session after decryption.
type decrypted struct {
	handshake [][2][]byte // (type, body) messages from the encrypted handshake
	app       []byte
	err       error
}

// decrypt13 decrypts one direction's encrypted records: handshake keys until
// Finished, then application traffic keys, following KeyUpdate.
func decrypt13(recs []record, s suite13, hsSecret, appSecret []byte, appCap int) decrypted {
	var d decrypted
	if hsSecret == nil || appSecret == nil {
		d.err = errors.New("the key log has no secrets for this session")
		return d
	}
	keys, err := newTrafficKeys(s, hsSecret)
	if err != nil {
		d.err = err
		return d
	}
	inHandshake := true
	var hsBuf []byte
	for _, r := range recs {
		if r.typ == 20 { // compatibility ChangeCipherSpec
			continue
		}
		if r.typ != 23 {
			continue
		}
		pt, ct, err := keys.open(r)
		if err != nil {
			d.err = errors.New("a record failed to decrypt with the logged secrets (wrong or missing key log entry, or records the capture missed)")
			return d
		}
		switch ct {
		case 22:
			hsBuf = append(hsBuf, pt...)
			msgs := handshakeMessages(hsBuf)
			consumed := 0
			for _, m := range msgs {
				consumed += 4 + len(m[1])
				d.handshake = append(d.handshake, m)
				switch m[0][0] {
				case 20: // Finished: switch to application keys
					if inHandshake {
						inHandshake = false
						if keys, err = newTrafficKeys(s, appSecret); err != nil {
							d.err = err
							return d
						}
					}
				case 24: // KeyUpdate
					if !inHandshake {
						if keys, err = keys.update(); err != nil {
							d.err = err
							return d
						}
					}
				}
			}
			hsBuf = hsBuf[consumed:]
		case 23:
			if len(d.app) < appCap {
				d.app = append(d.app, pt[:min(len(pt), appCap-len(d.app))]...)
			}
		}
	}
	return d
}
