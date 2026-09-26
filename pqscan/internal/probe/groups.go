package probe

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"pqscan/internal/mlkem"
)

// TLS "supported group" (named group / CurveID) code points.
// Sources: IANA TLS Supported Groups registry; draft-ietf-tls-ecdhe-mlkem
// (hybrid ML-KEM groups); the legacy Chrome/Cloudflare draft group.
const (
	GroupX25519             uint16 = 0x001D // 29
	GroupSecP256r1          uint16 = 0x0017 // 23
	GroupSecP384r1          uint16 = 0x0018 // 24
	GroupX25519MLKEM768     uint16 = 0x11EC // 4588  (ML-KEM first)
	GroupSecP256r1MLKEM768  uint16 = 0x11EB // 4587  (ECDH first)
	GroupSecP384r1MLKEM1024 uint16 = 0x11ED // 4589 (ECDH first)
	GroupX25519Kyber768D00  uint16 = 0x6399 // 25497 legacy draft (deprecated)
)

// Group describes a named group we can probe for.
type Group struct {
	ID   uint16
	Name string
	PQ   bool // true if the group provides post-quantum key exchange
	// Legacy marks groups whose "not supported" result is low-confidence because
	// we cannot mint a share the server will accept (see buildKeyShare).
	Legacy bool
}

// PQGroups is the set of post-quantum (hybrid) groups the scanner probes, in a
// sensible reporting order. All are hybrid (classical + ML-KEM/Kyber).
var PQGroups = []Group{
	{ID: GroupX25519MLKEM768, Name: "X25519MLKEM768", PQ: true},
	{ID: GroupSecP256r1MLKEM768, Name: "SecP256r1MLKEM768", PQ: true},
	{ID: GroupSecP384r1MLKEM1024, Name: "SecP384r1MLKEM1024", PQ: true},
	{ID: GroupX25519Kyber768D00, Name: "X25519Kyber768Draft00", PQ: true, Legacy: true},
}

// GroupName returns a human-readable name for any group code point we know.
func GroupName(id uint16) string {
	switch id {
	case GroupX25519:
		return "X25519"
	case GroupSecP256r1:
		return "secp256r1"
	case GroupSecP384r1:
		return "secp384r1"
	case GroupX25519MLKEM768:
		return "X25519MLKEM768"
	case GroupSecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	case GroupSecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024"
	case GroupX25519Kyber768D00:
		return "X25519Kyber768Draft00"
	default:
		return fmt.Sprintf("0x%04X", id)
	}
}

// buildKeyShare returns a valid TLS 1.3 client key_share key_exchange for the
// given group, generating fresh, well-formed key material with the standard
// library. The concatenation order per group follows draft-ietf-tls-ecdhe-mlkem:
//   - X25519MLKEM768:      ML-KEM-768 ek  || X25519 pub    (ML-KEM first)
//   - SecP256r1MLKEM768:   P-256 pub      || ML-KEM-768 ek (ECDH first)
//   - SecP384r1MLKEM1024:  P-384 pub      || ML-KEM-1024 ek(ECDH first)
//
// The legacy X25519Kyber768Draft00 used Kyber (round-3), which crypto/mlkem does
// not produce; we approximate with an ML-KEM-768-sized share so that a *positive*
// (server selects it) is meaningful, while a negative is low-confidence.
func buildKeyShare(id uint16) ([]byte, error) {
	switch id {
	case GroupX25519:
		return ecdhPub(ecdh.X25519())
	case GroupSecP256r1:
		return ecdhPub(ecdh.P256())
	case GroupSecP384r1:
		return ecdhPub(ecdh.P384())

	case GroupX25519MLKEM768:
		ek, err := mlkem.EncapKey768()
		if err != nil {
			return nil, err
		}
		x, err := ecdhPub(ecdh.X25519())
		if err != nil {
			return nil, err
		}
		return append(ek, x...), nil // ML-KEM first

	case GroupSecP256r1MLKEM768:
		p, err := ecdhPub(ecdh.P256())
		if err != nil {
			return nil, err
		}
		ek, err := mlkem.EncapKey768()
		if err != nil {
			return nil, err
		}
		return append(p, ek...), nil // ECDH first

	case GroupSecP384r1MLKEM1024:
		p, err := ecdhPub(ecdh.P384())
		if err != nil {
			return nil, err
		}
		ek, err := mlkem.EncapKey1024()
		if err != nil {
			return nil, err
		}
		return append(p, ek...), nil // ECDH first

	case GroupX25519Kyber768D00:
		// Best-effort: Kyber round-3 key not available from crypto/mlkem.
		x, err := ecdhPub(ecdh.X25519())
		if err != nil {
			return nil, err
		}
		ek, err := mlkem.EncapKey768()
		if err != nil {
			return nil, err
		}
		return append(x, ek...), nil // draft00 order: X25519 first

	default:
		return nil, fmt.Errorf("unknown group 0x%04X", id)
	}
}

func ecdhPub(c ecdh.Curve) ([]byte, error) {
	k, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}
