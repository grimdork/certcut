package certcut

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type asn struct {
	N *big.Int
	E int
}

// NewTemplate for server and client certificates.
func NewTemplate() *x509.Certificate {
	return &x509.Certificate{
		AuthorityKeyId:              nil,
		BasicConstraintsValid:       false,
		DNSNames:                    nil,
		ExcludedDNSDomains:          nil,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                        false,
		KeyUsage:                    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		NotAfter:                    time.Time{},
		NotBefore:                   time.Now(),
		PermittedDNSDomains:         nil,
		PermittedDNSDomainsCritical: false,
		SerialNumber:                big.NewInt(1),
		SignatureAlgorithm:          0,
		Subject:                     pkix.Name{},
		SubjectKeyId:                nil,
		UnknownExtKeyUsage:          nil,
	}
}

// HashSubjectKeyID returns the hash for a public key.
func HashSubjectKeyID(key *rsa.PublicKey) ([]byte, error) {
	b, err := asn1.Marshal(asn{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}

	hash := sha1.Sum(b)
	return hash[:], nil
}

// NewSerial generates a random BigInt.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(0), err
	}

	return serial, nil
}

// NewCA creates a new certificate authority which further client certificates can be generated with.
func NewCA(key *rsa.PrivateKey, subject pkix.Name) ([]byte, error) {
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}

	tpl := NewTemplate()
	tpl.BasicConstraintsValid = true
	tpl.IsCA = true
	tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tpl.SerialNumber = serial
	tpl.Subject = subject

	id, err := HashSubjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	tpl.SubjectKeyId = id
	tpl.NotAfter = time.Now().AddDate(10, 0, 0)

	buf, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

// NewClientCert makes certificates for client authentication.
func NewClientCert(key *rsa.PrivateKey, cn string, ca []byte, csr *x509.CertificateRequest) ([]byte, error) {
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}

	auth, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, err
	}

	tpl := NewTemplate()

	id, err := HashSubjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	tpl.SubjectKeyId = id
	tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	tpl.SerialNumber = serial
	tpl.NotBefore = auth.NotBefore
	tpl.NotAfter = auth.NotAfter

	tpl.Subject = pkix.Name{
		CommonName:   cn,
		Country:      []string{},
		Organization: []string{},
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, auth, csr.PublicKey, key)

	if err != nil {
		return nil, err
	}

	return cert, nil
}
