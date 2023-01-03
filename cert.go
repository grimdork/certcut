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
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

// NewCA creates a new certificate authority which further client certificates can be generated with.
// The NotAfter date is set to 10 years from now.
func NewCA(key *rsa.PrivateKey, cn string) ([]byte, error) {
	tpl := NewTemplate()
	tpl.Subject = pkix.Name{
		CommonName:   cn,
		Country:      []string{},
		Organization: []string{},
	}

	return NewCAFromTemplate(key, tpl)
}

// NewCAFromTemplate creates a new certificate authority from a template for more control. The minimum field required is CommonName.
// A serial number will be generated, and empty dates will be filled in with the same defaults as NewCA.
// Empty KeyUsage fields will be filled in with x509.KeyUsageCertSign | x509.KeyUsageCRLSign.
func NewCAFromTemplate(key *rsa.PrivateKey, tpl *x509.Certificate) ([]byte, error) {
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}

	tpl.SerialNumber = serial
	tpl.BasicConstraintsValid = true
	tpl.IsCA = true
	if tpl.KeyUsage == 0 {
		tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	id, err := HashSubjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	tpl.SubjectKeyId = id
	tpl.NotAfter = time.Now().AddDate(10, 0, 0)
	buf, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return buf, err
}

// NewClientCert makes certificates for client authentication.
func NewClientCert(authkey *rsa.PrivateKey, hostkey *rsa.PrivateKey, cn string, ca *x509.Certificate, csr *x509.CertificateRequest) ([]byte, error) {
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}

	tpl := NewTemplate()
	tpl.BasicConstraintsValid = true
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tpl.SerialNumber = serial
	tpl.NotBefore = ca.NotBefore
	tpl.NotAfter = ca.NotAfter
	tpl.MaxPathLenZero = false

	tpl.Subject = pkix.Name{
		CommonName:   cn,
		Country:      []string{},
		Organization: []string{},
	}

	id, err := HashSubjectKeyID(&hostkey.PublicKey)
	if err != nil {
		return nil, err
	}

	tpl.SubjectKeyId = id
	tpl.Issuer = ca.Subject
	cert, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, authkey)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// NewRootCert creates a root certificate and its key in one function.
func NewRootCert(cn string, bits int) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := NewKey(bits)
	if err != nil {
		return nil, nil, err
	}

	b, err := NewCA(key, cn)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}
