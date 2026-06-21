# mTLS-core

A generic, drop-in mutual-TLS foundation: one private CA, a cert per service, and
ready-made `tls.Config` builders so any service authenticates its peers
cryptographically over an encrypted, integrity-protected channel. Standard
library only — **no external dependencies**. Designed to be swapped into existing
or future projects quickly and correctly, every time.

## Why
A bearer token over plain HTTP is sniffable and replayable on a shared network.
mTLS fixes the root cause: **mutual identity** (both ends present a CA-signed
cert), **confidentiality + integrity** (per-session keys), and — at `MinVersion`
TLS 1.3 on Go ≥1.24 — the **X25519MLKEM768 hybrid key exchange**, i.e.
post-quantum confidentiality (defeats harvest-now-decrypt-later) for free.

> Honest scope: transport confidentiality is post-quantum. Certificate
> **signatures** are ECDSA-P256 (classical) — an acceptable interim, since cert
> forgery is a future threat, not a harvest-now one; swap to ML-DSA when Go's
> PQ-signature tooling matures. A symmetric bearer token (256-bit) remains a fine
> app-layer defense-in-depth *inside* the mTLS tunnel.

## Layout
- `certgen/` — `CA` (create/load), `Issue` leaf certs, PEM I/O, fingerprints.
- `mtls/` — `ServerConfig` (`RequireAndVerifyClientCert`) and `ClientConfig`.
- `cmd/mtls/` — CLI to bootstrap the CA and issue certs (PEM for any language).

## Quick start (CLI)
```bash
go build -o build/mtls ./cmd/mtls

# 1. Bootstrap the CA once (keep ca.key secret; distribute ca.crt to every peer):
./build/mtls init-ca --org "my-fleet" --dir ./secrets

# 2. Issue a cert per service, with the SANs it is reached at:
./build/mtls issue --dir ./secrets --name svc-a \
    --dns localhost,svc-a.internal --ip <ip-list> --out ./secrets/svc-a
```

## Integrate — Go service
```go
caPEM, _ := os.ReadFile("ca.crt")
pool := x509.NewCertPool(); pool.AppendCertsFromPEM(caPEM)
crt, _ := os.ReadFile("svc.crt"); key, _ := os.ReadFile("svc.key")

// inbound server:
sc, _ := mtls.ServerConfig(crt, key, pool)
srv := &http.Server{Addr: ":8443", TLSConfig: sc, Handler: h}
srv.ListenAndServeTLS("", "")

// outbound client (serverName must match a SAN on the peer's cert):
cc, _ := mtls.ClientConfig(crt, key, pool, "peer-host")
client := &http.Client{Transport: &http.Transport{TLSClientConfig: cc}}
```

## Integrate — other languages (same CA / PEMs)
The CA and certs are plain PEM, so non-Go services use their stdlib TLS:
- **Python:** `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` → `load_cert_chain(svc.crt,
  svc.key)`, `load_verify_locations(ca.crt)`, `verify_mode = ssl.CERT_REQUIRED`;
  the client side mirrors with a client context + `check_hostname`.
- **Node:** `https.createServer({cert, key, ca, requestCert:true,
  rejectUnauthorized:true})`; outbound `new https.Agent({cert, key, ca})`.

## Verify
`go build ./... && go vet ./... && go test ./...` — `TestMutualTLS` proves a real
handshake: valid mutual auth → TLS 1.3; no client cert → rejected; cert from an
untrusted CA → rejected.

## Security notes
- `ca.key` is the root of trust — store it locked (0600), ideally offline; it is
  gitignored here and must never be committed.
- Rotate leaf certs on a schedule (`--days`); re-issue and restart the service.
- mTLS authenticates; still bind services only to the interfaces they need.
