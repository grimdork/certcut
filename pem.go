package certcut

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// PrivateKeyPEM converts a private key to PEM format.
func PrivateKeyPEM(key *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}

// PublicKeyPEM converts a public key to PEM format.
func PublicKeyPEM(key *rsa.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// CertPEM converts a certificate to PEM format.
func CertPEM(b []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}
	return pem.EncodeToMemory(block)
}

// CSRPEM converts a certificate signing request to PEM format.
func CSRPEM(b []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: b,
	}

	return pem.EncodeToMemory(block)
}
