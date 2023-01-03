package certcut

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// LoadPrivateKeyFromPEM returns a parsed private key structure.
func LoadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	keypem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keypem)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadPublicKeyFromPEM returns a parsed private key structure.
func LoadPublicKeyFromPEM(path string) (interface{}, error) {
	keypem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keypem)
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// LoadCertFromPEM returns the raw bytes of a certificate.
func LoadCertFromPEM(path string) ([]byte, error) {
	certpem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certpem)
	return block.Bytes, nil
}

// LoadCSRFromPEM returns an x509 CertificateRequest.
func LoadCSRFromPEM(path string) (*x509.CertificateRequest, error) {
	csrpem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(csrpem)
	return x509.ParseCertificateRequest(block.Bytes)
}
