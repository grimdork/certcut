# certcut

Quick certificate generation and loading.

## Install

go get -u github.com/Urethramancer/certcut

## Why

I needed simpler, automated generation of self-signed server and client certificates for various projects, both gRPC client certificate authentication and general web servers.

## How

Example of generating a server certificate:

```go
// Create a server key
key, err := certcut.NewKey(4096) // 2048 is the default if you supply anything less
if err != nil {
	return err
}
// Get the PEM with PrivateKeyPEM()
// Once saved, you can load it with LoadPrivateKeyFromPEM()

// Create a certificate authority (server certificate)
b, err := certcut.NewCA(key, "MiskatonicU")
if err != nil {
	return err
}
// Get the PEM with CertPEM()
// Load it again with LoadCertFromPEM()

// Create a certificate revocation list
crl, err := certcut.NewCRL(key, b, nil) // Supply []pkix.RevokedCertificate as the last argument
if err != nil {
	return err
}
// Get the PEM with CRLPEM()
// Load it with LoadCRLFromPEM()

```

Note that this package only cares about the Common Name for certificates etc., as it's intended for internal use and not to generate certificates/signing requests for a public CA.

Signing host (client) certificates:
```go
// Continuing from the above example, we generate the key and cert for a client.

// Create a client key
clientkey, err := certcut.NewKey(4096)
if err != nil {
	return err
}
// Get the PEM with PrivateKeyPEM()

cn := "WDyer"
// Generate a certificate signing request
csrbuf, err := certcut.NewCSR(clientkey, cn)
if err != nil {
	return err
}
// It's not strictly necessary to store these, especially for internal use,
// but you are free to use CSRPEM() if you need it. A corresponding
// LoadCSRFromPem() function is also available.

csr, err := x509.ParseCertificateRequest(csrbuf)
if err != nil {
	return err
}

cacrt, err := certcut.NewClientCert(serverkey, clientkey, cn, ca, csr)
if err != nil {
	return err
}
```

### gRPC

There's a convenience function for the grpc package to load both the CA cert and the client cert at once into a TLS config:

```go
creds, err := certcut.NewClientTLSFromFiles("server.crt", "client.crt", "client.key")
...
conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
```

It's a drop-in replacement for gRPC's NewClientTLSFromFile().
