// Package mlkem is a thin wrapper over the standard library's crypto/mlkem.
//
// The scanner only ever needs a *valid, well-formed* ML-KEM encapsulation key to
// place in a TLS key_share: servers validate the key's encoding (FIPS 203) and will
// reject a malformed one, falling back to a classical group and producing a false
// "not ready" reading. We never use the resulting shared secret — we read the
// server's chosen group and disconnect — so the key need not be secret or reused;
// crypto/mlkem mints a fresh valid one at runtime and no key material is embedded.
package mlkem

import "crypto/mlkem"

// EncapKey768 returns the bytes of a freshly generated, valid ML-KEM-768
// encapsulation key (1184 bytes), as used in the X25519MLKEM768 and
// SecP256r1MLKEM768 hybrid TLS key shares.
func EncapKey768() ([]byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}

// EncapKey1024 returns the bytes of a freshly generated, valid ML-KEM-1024
// encapsulation key (1568 bytes), as used in the SecP384r1MLKEM1024 hybrid TLS
// key share.
func EncapKey1024() ([]byte, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}
