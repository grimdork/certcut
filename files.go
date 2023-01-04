package certcut

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// LoadPrivateKeyFromPEM returns a parsed private key structure.
func LoadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	keypem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keypem)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadPublicKeyFromPEM returns a parsed private key structure.
func LoadPublicKeyFromPEM(path string) (any, error) {
	keypem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keypem)
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// LoadCertFromPEM returns the raw bytes of a certificate.
func LoadCertFromPEM(path string) (*x509.Certificate, error) {
	certpem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certpem)
	crt, err := x509.ParseCertificate(block.Bytes)
	return crt, err
}

// LoadCSRFromPEM returns an x509 CertificateRequest.
func LoadCSRFromPEM(path string) (*x509.CertificateRequest, error) {
	csrpem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(csrpem)
	return x509.ParseCertificateRequest(block.Bytes)
}
