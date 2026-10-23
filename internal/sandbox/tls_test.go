package sandbox

import (
	"crypto/x509"
	"testing"
)

func TestNewCertificateIsOnlyTrustedForTheModelProxyHost(t *testing.T) {
	caPEM, cert, err := newCertificate("host.docker.internal")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "host.docker.internal"}); err != nil {
		t.Fatalf("the container would reject the model proxy: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "chatgpt.com"}); err == nil {
		t.Fatal("the certificate is valid for another host")
	}
	if leaf.IsCA {
		t.Fatal("the server certificate can sign certificates")
	}
}
