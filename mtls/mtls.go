// Package mtls builds drop-in mutual-TLS configs from PEM material. Both sides
// require the peer's certificate to chain to the shared CA, so identity is
// mutual and the channel is encrypted + integrity-protected. MinVersion is
// TLS 1.3, which on Go 1.24+ negotiates the X25519MLKEM768 hybrid key exchange
// — post-quantum confidentiality (defeats harvest-now-decrypt-later) for free.
//
// Usage:
//
//	srvCfg, _ := mtls.ServerConfig(certPEM, keyPEM, caPool); http.Server{TLSConfig: srvCfg}
//	cliCfg, _ := mtls.ClientConfig(certPEM, keyPEM, caPool, "peer-host")
//	&http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// ServerConfig returns a TLS 1.3 mutual-TLS config: it presents (certPEM,keyPEM)
// and REQUIRES + verifies the client's certificate against caPool.
func ServerConfig(certPEM, keyPEM []byte, caPool *x509.CertPool) (*tls.Config, error) {
	if caPool == nil {
		return nil, errors.New("mtls: nil CA pool")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientConfig returns a TLS 1.3 config that presents (certPEM,keyPEM) and
// verifies the server's certificate against caPool. serverName must match a SAN
// on the server's certificate.
func ClientConfig(certPEM, keyPEM []byte, caPool *x509.CertPool, serverName string) (*tls.Config, error) {
	if caPool == nil {
		return nil, errors.New("mtls: nil CA pool")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
