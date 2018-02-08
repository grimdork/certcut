# certcut

Quick certificate generation and loading.

## Why

I needed simpler, automated generation of self-signed server and client certificates for various projects, both gRPC client certificate authentication and general web servers.

## How

The functions should be fairly self-explanatory, but here's a quick overview.

### Install

go get -u github.com/Urethramancer/certcut

### Keys

To generate a new 4096-bit key:

```go
key,err := certcut.NewKey(4096)
...
```

A pointer to an rsa.PrivateKey is returned.

- Export the private and public keys to PEM with `PrivateKeyPEM()` and `PublicKeyPEM()`
- Load them with `LoadPrivateKeyFromPEM()` and `LoadPublicKeyFromPEM()`.

### Certificates

Generate a new certificate authority:

```go
subject := pkix.Name{
    CommonName:   "miskatonic.edu",
    Country:      []string{"AQ"},
    Organization: []string{"MU"},
}
bytes,err := NewCA(key, subject)
...
```

The subject is a pkix.Name structure.

Generate a new client certificate:

```go
...
bytes,err := NewCA(key, subject)
...
````

- Export it to PEM with `CertPEM()`
- Load it with `LoadCertFromPEM()`

### Certificate revocation lists

Create it like this:

```go
list :=  []pkix.RevokedCertificate{...}
bytes,err := NewCRL(key, cert, list)
...
```

- Export it to PEM with `CRLPEM()`
- Load it with `LoadCRLFromPEM()`

### Certificate signing request

Generate it like this:

```go
bytes,err := NewCSR(key, cn)
...
```

- Export it to PEM with `CSRPEM()`
- Load it with `LoadCSRFromPEM()`
