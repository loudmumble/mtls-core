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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

// Identity is the verified identity of a TLS peer, derived from its leaf
// certificate AFTER a successful mutual-TLS handshake. It is observed from the
// connection, never taken from the request body — so a caller cannot forge it
// without the corresponding private key. This is the basis of channel-binding:
// authorize on PeerIdentity, not on self-reported names or shared tokens.
type Identity struct {
	// URI is the first URI SAN (e.g. spiffe://fleet/agent/athena) — the stable,
	// CA-issued identity. Empty when the certificate carries no URI SAN.
	URI string
	// Name is the short identity name: the last path segment of the URI SAN, or
	// the certificate CommonName when there is no URI SAN. (Existing fleet certs
	// have no URI SAN, so this falls back to CN — channel-binding works today.)
	Name string
	// SPKIFingerprint is the hex SHA-256 of the peer's SubjectPublicKeyInfo —
	// stable across key-preserving renewals; used as the enrollment pin.
	SPKIFingerprint string
}

// PeerIdentity extracts the verified Identity from a completed mTLS handshake
// (e.g. (*http.Request).TLS). It errors when no peer certificate is present —
// i.e. the connection is not authenticated mutual TLS — so callers fail closed.
func PeerIdentity(cs *tls.ConnectionState) (Identity, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return Identity{}, errors.New("mtls: no peer certificate (connection is not authenticated mutual TLS)")
	}
	leaf := cs.PeerCertificates[0]
	id := Identity{}
	if len(leaf.URIs) > 0 {
		id.URI = leaf.URIs[0].String()
		if seg := lastSegment(leaf.URIs[0].Path); seg != "" {
			id.Name = seg
		}
	}
	if id.Name == "" {
		id.Name = leaf.Subject.CommonName
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	id.SPKIFingerprint = hex.EncodeToString(sum[:])
	return id, nil
}

func lastSegment(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

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
