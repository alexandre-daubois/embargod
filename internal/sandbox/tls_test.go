package sandbox

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCertificateIsOnlyTrustedForTheModelProxyHost(t *testing.T) {
	caPEM, cert, err := newCertificate("host.docker.internal")
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM), "the CA is not valid PEM")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "host.docker.internal"})
	require.NoError(t, err, "the container would reject the model proxy")
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "chatgpt.com"})
	require.Error(t, err, "the certificate is valid for another host")
	require.False(t, leaf.IsCA, "the server certificate can sign certificates")
}
