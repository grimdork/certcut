package certcut

import (
	"crypto/rsa"
	"crypto/x509"
)

// GetSignedCert returns a signed client certificate and key signed by the provided CA.
// It creates a CSR and discards it after use. The returned key is 4096 bits.
func GetSignedCert(ca *x509.Certificate, cakey *rsa.PrivateKey, name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := NewKey(4096)
	if err != nil {
		return nil, nil, err
	}

	csrbuf, err := NewCSR(key, name)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrbuf)
	if err != nil {
		return nil, nil, err
	}

	b, err := NewClientCert(cakey, key, name, ca, csr)
	if err != nil {
		return nil, nil, err
	}

	crt, err := x509.ParseCertificate(b)
	return crt, key, err
}
