package mtls

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/loudmumble/mtls-core/certgen"
)

// End-to-end proof: a server built with ServerConfig and a client built with
// ClientConfig complete a mutual TLS 1.3 handshake; a client with no cert or a
// cert from another CA is rejected.
func TestMutualTLS(t *testing.T) {
	ca, err := certgen.NewCA("test-fleet", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.Issue("server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, err := ca.Issue("client", nil, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	srvCfg, err := ServerConfig(srvCert, srvKey, ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	// 1) Valid mutual handshake → negotiates TLS 1.3.
	cliCfg, err := ClientConfig(cliCert, cliKey, ca.Pool(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg}}).Get(ts.URL)
	if err != nil {
		t.Fatalf("valid mTLS handshake failed: %v", err)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version %#x, want 1.3", versionOf(resp))
	}
	resp.Body.Close()

	// 2) Client with NO certificate → rejected.
	noCert := &tls.Config{RootCAs: ca.Pool(), ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noCert}}).Get(ts.URL); err == nil {
		t.Fatal("server accepted a client with no certificate")
	}

	// 3) Client cert from a DIFFERENT (untrusted) CA → rejected.
	evil, err := certgen.NewCA("evil", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	eCert, eKey, err := evil.Issue("client", nil, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	badCfg, err := ClientConfig(eCert, eKey, ca.Pool(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: badCfg}}).Get(ts.URL); err == nil {
		t.Fatal("server accepted a client cert from an untrusted CA")
	}
}

func versionOf(r *http.Response) uint16 {
	if r.TLS == nil {
		return 0
	}
	return r.TLS.Version
}

// TestPeerIdentity proves channel-binding: the server derives identity from the
// peer cert it OBSERVES on the handshake — CN when there is no URI SAN, the URI
// SAN's last segment when present — plus a stable SPKI pin, and fails closed
// when there is no peer cert.
func TestPeerIdentity(t *testing.T) {
	ca, err := certgen.NewCA("test-fleet", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.Issue("server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg, err := ServerConfig(srvCert, srvKey, ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	// The server echoes the identity it observes from the peer certificate.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := PeerIdentity(r.TLS)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		io.WriteString(w, id.Name+"|"+id.URI+"|"+id.SPKIFingerprint)
	}))
	ts.TLS = srvCfg
	ts.StartTLS()
	defer ts.Close()

	call := func(cert, key []byte) []string {
		t.Helper()
		cfg, err := ClientConfig(cert, key, ca.Pool(), "localhost")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}).Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.SplitN(string(b), "|", 3)
	}

	// 1) CN fallback — cert with CN=athena, no URI SAN (today's fleet certs).
	cnCert, cnKey, err := ca.Issue("athena", nil, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got := call(cnCert, cnKey)
	if got[0] != "athena" {
		t.Fatalf("CN-fallback name = %q, want athena", got[0])
	}
	if got[1] != "" {
		t.Fatalf("expected empty URI for a CN-only cert, got %q", got[1])
	}
	if len(got[2]) != 64 {
		t.Fatalf("SPKI fingerprint = %q (len %d), want 64 hex chars", got[2], len(got[2]))
	}

	// 2) URI SAN — spiffe://fleet/agent/athena resolves Name to the last segment.
	u, _ := url.Parse("spiffe://fleet/agent/athena")
	uriCert, uriKey, err := ca.IssueURI("athena-leaf", nil, nil, []*url.URL{u}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got = call(uriCert, uriKey)
	if got[0] != "athena" {
		t.Fatalf("URI-derived name = %q, want athena", got[0])
	}
	if got[1] != "spiffe://fleet/agent/athena" {
		t.Fatalf("URI = %q, want spiffe://fleet/agent/athena", got[1])
	}

	// 3) Fail closed — no peer certificate / no connection state.
	if _, err := PeerIdentity(nil); err == nil {
		t.Fatal("PeerIdentity(nil) must error (fail closed)")
	}
}
