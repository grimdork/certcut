package certcut

import (
	"crypto/rand"
	"crypto/rsa"
)

// NewKey creates a new RSA key for certificate generation and signing.
func NewKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = 2048
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return key, nil
}
