package certgen

import (
	"net"
	"testing"
	"time"
)

func TestCAIssueAndReload(t *testing.T) {
	ca, err := NewCA("test-fleet", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := ca.Issue("svc", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("issued empty PEM")
	}

	// CA round-trips through PEM.
	cp, kp, err := ca.PEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	// Fingerprint is non-empty and stable.
	fp1, err := Fingerprint(certPEM)
	if err != nil || fp1 == "" {
		t.Fatalf("fingerprint: %q err=%v", fp1, err)
	}
	if fp2, _ := Fingerprint(certPEM); fp2 != fp1 {
		t.Fatal("fingerprint not stable")
	}
}
