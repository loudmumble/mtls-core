package mtls

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
