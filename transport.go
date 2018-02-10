package certcut

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"google.golang.org/grpc/credentials"
)

// NewClientTLSFromFiles is an improved version of gRPC's NewClientTLSFromFile which also loads the root
// certificate for the certificate authority so that connections actually work with verification.
func NewClientTLSFromFiles(servercert, clientcert, clientkey string) (credentials.TransportCredentials, error) {
	var tlsConf tls.Config

	crt, err := tls.LoadX509KeyPair(clientcert, clientkey)
	if err != nil {
		return nil, fmt.Errorf("could not load client key pair: %v", err)
	}
	tlsConf.Certificates = []tls.Certificate{crt}

	pool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(servercert)
	if err != nil {
		return nil, fmt.Errorf("could not read CA certificate: %v", err)
	}

	// Append the certificates from the CA
	if ok := pool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("failed to append CA certs")
	}

	tlsConf.RootCAs = pool
	return credentials.NewTLS(&tlsConf), nil
}
