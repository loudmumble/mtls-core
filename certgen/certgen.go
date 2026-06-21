// Package certgen provides a private certificate authority and leaf-certificate
// issuance for mutual TLS, using the Go standard library only (no external
// dependencies). It is the crypto core of mTLS-core: bootstrap one CA, issue a
// cert per service, and every service mutually authenticates against the shared
// CA. Pattern adapted from a proven in-house implementation (Burrow's certgen).
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is a certificate authority: its certificate (the trust root) and key.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// NewCA creates a new self-signed CA (ECDSA P-256) valid for `validity`.
func NewCA(org string, validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	sn, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaf certs only, no sub-CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: pemBlock("CERTIFICATE", der)}, nil
}

// LoadCA parses a CA from PEM certificate + key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not ECDSA")
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// Pool returns a cert pool containing the CA — the trust root for verifying peers.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// PEM returns the CA certificate and private key as PEM bytes.
func (ca *CA) PEM() (certPEM, keyPEM []byte, err error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, nil, err
	}
	return ca.CertPEM, pemBlock("PRIVATE KEY", keyDER), nil
}

// Issue creates a leaf certificate signed by the CA, valid for BOTH server and
// client auth (every fleet service is both). cn is the CommonName; dnsNames and
// ips are the Subject Alternative Names the cert is valid for.
func (ca *CA) Issue(cn string, dnsNames []string, ips []net.IP, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// Fingerprint returns the SHA-256 hex of a PEM certificate (for pinning/audit).
func Fingerprint(certPEM []byte) (string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return "", errors.New("invalid certificate PEM")
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// WriteFile writes data to path with 0600 perms, creating parent dirs (0700).
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
