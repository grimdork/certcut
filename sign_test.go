package certcut_test

import (
	"testing"

	"github.com/grimdork/certcut"
)

func TestNewKey(t *testing.T) {
	key, err := certcut.NewKey(0)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(certcut.PrivateKeyPEM(key)))
}

func TestNewRootCert(t *testing.T) {
	crt, key, err := certcut.NewRootCert("Test CA", 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(certcut.CertPEM(crt.Raw)))
	t.Log(string(certcut.PrivateKeyPEM(key)))
}

func TestGetSignedCert(t *testing.T) {
	cacert, cakey, err := certcut.NewRootCert("Test CA", 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Generated root certificate and key.")
	crt, _, err := certcut.GetSignedCert(cacert, cakey, "Test Client")
	if err != nil {
		t.Fatal(err)
	}

	err = crt.CheckSignatureFrom(cacert)
	if err != nil {
		t.Fatalf("Signature check failed: %s", err)
	}
}
