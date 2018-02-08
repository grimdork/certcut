package certcut

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
)

// NewCSR creates a new certificate signing request.
func NewCSR(key *rsa.PrivateKey, cn string) ([]byte, error) {
	subject := pkix.Name{
		CommonName:   cn,
		Country:      []string{},
		Organization: []string{},
	}

	tpl := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, err
	}

	return csr, nil
}
