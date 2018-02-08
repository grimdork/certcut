package certcut

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// NewCRL creates a new certificate revocation list.
func NewCRL(key *rsa.PrivateKey, cert []byte, list []pkix.RevokedCertificate) ([]byte, error) {
	crt, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return crt.CreateCRL(rand.Reader, key, list, time.Now(), time.Now().AddDate(1, 0, 0))
}
