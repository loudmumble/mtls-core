// Command mtls bootstraps a fleet CA and issues per-service certificates for
// mTLS-core. The output is plain PEM, usable from any language (Go imports the
// packages directly; Python/Node load the .crt/.key files).
//
//	mtls init-ca --org NAME --dir DIR [--days 3650]
//	mtls issue   --dir DIR --name NAME [--dns a,b] [--ip <ip-list>] [--uri spiffe://fleet/agent/NAME] [--out DIR] [--days 825]
package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loudmumble/mtls-core/certgen"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init-ca":
		initCA(os.Args[2:])
	case "issue":
		issue(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mtls — mTLS-core CA + certificate tool

  mtls init-ca --org NAME --dir DIR [--days 3650]
        Create a fleet CA (ca.crt, ca.key) in DIR.

  mtls issue --dir DIR --name NAME [--dns a,b] [--ip <ip-list>] [--out DIR] [--days 825]
        Issue NAME.crt / NAME.key signed by the CA in DIR (valid for server AND client auth).`)
	os.Exit(2)
}

func initCA(args []string) {
	fs := flag.NewFlagSet("init-ca", flag.ExitOnError)
	org := fs.String("org", "fleet", "organization / CA name")
	dir := fs.String("dir", ".", "output directory for ca.crt/ca.key")
	days := fs.Int("days", 3650, "validity in days")
	_ = fs.Parse(args)

	ca, err := certgen.NewCA(*org, time.Duration(*days)*24*time.Hour)
	check(err)
	certPEM, keyPEM, err := ca.PEM()
	check(err)
	check(certgen.WriteFile(filepath.Join(*dir, "ca.crt"), certPEM))
	check(certgen.WriteFile(filepath.Join(*dir, "ca.key"), keyPEM))
	fmt.Printf("CA created: %s, %s\n", filepath.Join(*dir, "ca.crt"), filepath.Join(*dir, "ca.key"))
}

func issue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory holding ca.crt/ca.key")
	name := fs.String("name", "", "service name (CommonName + output filename)")
	dns := fs.String("dns", "localhost", "comma-separated DNS SANs")
	ips := fs.String("ip", "", "comma-separated IP SANs")
	uris := fs.String("uri", "", "comma-separated URI SANs (e.g. spiffe://fleet/agent/athena)")
	out := fs.String("out", "", "output directory (default: --dir)")
	days := fs.Int("days", 825, "validity in days")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "issue: --name is required")
		os.Exit(2)
	}
	if *out == "" {
		*out = *dir
	}

	caCert, err := os.ReadFile(filepath.Join(*dir, "ca.crt"))
	check(err)
	caKey, err := os.ReadFile(filepath.Join(*dir, "ca.key"))
	check(err)
	ca, err := certgen.LoadCA(caCert, caKey)
	check(err)

	var ipList []net.IP
	for _, s := range splitCSV(*ips) {
		if ip := net.ParseIP(s); ip != nil {
			ipList = append(ipList, ip)
		} else {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid IP %q\n", s)
		}
	}

	var uriList []*url.URL
	for _, s := range splitCSV(*uris) {
		u, perr := url.Parse(s)
		if perr != nil || u.Scheme == "" {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid URI %q\n", s)
			continue
		}
		uriList = append(uriList, u)
	}

	certPEM, keyPEM, err := ca.IssueURI(*name, splitCSV(*dns), ipList, uriList, time.Duration(*days)*24*time.Hour)
	check(err)
	check(certgen.WriteFile(filepath.Join(*out, *name+".crt"), certPEM))
	check(certgen.WriteFile(filepath.Join(*out, *name+".key"), keyPEM))
	fmt.Printf("issued: %s, %s\n", filepath.Join(*out, *name+".crt"), filepath.Join(*out, *name+".key"))
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
