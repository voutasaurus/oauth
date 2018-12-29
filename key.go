package oauth

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/secretbox"
)

func NewKey() (*[32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

func EncryptBytes(key *[32]byte, b []byte) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	out := secretbox.Seal(nonce[:], b, &nonce, key)
	return out, nil
}

func DecryptBytes(key *[32]byte, b []byte) ([]byte, error) {
	if len(b) < 24 {
		return nil, ErrInvalidCipher
	}
	var nonce [24]byte
	copy(nonce[:], b)
	out, ok := secretbox.Open(nil, b[len(nonce):], &nonce, key)
	if !ok {
		return nil, ErrInvalidCipher
	}
	return out, nil
}
