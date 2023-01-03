# certcut

Quick certificate generation and loading.

## Install

go get -u github.com/grimdork/certcut

## Why

I needed simpler, automated generation of self-signed server and client certificates for various projects, both gRPC client certificate authentication and other servers.

## How

### Generating a server certificate

```go
// Create a server certificate and key
cacert, cakey, err := certcut.NewRootCert("Miskatonic U.", 4096) // 2048 is the default if you supply anything less
if err != nil {
	return err
}
```

Get the PEM with CertPEM() and PrivateKeyPEM(). You can load them with LoadCertFromPEM() and LoadPrivateKeyFromPEM(). Use `x509.CreateRevocationList()` to create CRLs, and load them with `x509.LoadCRLFromPEM()`.


Note that this package only cares about the Common Name for certificates etc., as it's intended for internal use and not to generate certificates/signing requests for a public CA.

### Signing a client certificate

```go
// Continuing from the above example, we generate the key and cert for a client.
// The key will be 4096 bits.
crt, key, err := certcut.GetSignedCert(cacert, cakey, "Staff")
if err != nil {
	return err
}
```

If you want more control over the process, for example to store the signing request, you can use NewCSR() to generate a CSR, and then NewClientCert() to sign it.

### gRPC

There's a convenience function for the grpc package to load both the CA cert and the client cert at once into a TLS config:

```go
creds, err := certcut.NewClientTLSFromFiles("server.crt", "client.crt", "client.key")
...
conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
```

It's a drop-in replacement for gRPC's NewClientTLSFromFile().
