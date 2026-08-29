# Standard-library implementation notes

`netwhy` uses no third-party Go modules and does not invoke external networking utilities. This document records the standard-library components used to implement features that are commonly handled by external packages or command-line tools.

## Dependency policy

* Zero third-party `require` entries in `go.mod`.
* No subprocesses (`os/exec`). No calls to `curl`, `dig`, `nslookup`, `openssl`, or `ping`.
* Standard library only for all networking, parsing, TLS, concurrency, and serialization logic.
* CGO-disabled builds are supported and verified with `CGO_ENABLED=0` on the tested platforms.

## Substitution table

| Capability | Common external option | Standard-library implementation |
|---|---|---|
| CLI parsing | Cobra / urfave/cli | `flag` with explicit subcommand routing |
| DNS wire queries | `miekg/dns` | `net`, `encoding/binary`, `crypto/rand` |
| HTTP client | Resty | `net/http` with isolated `http.Transport` instances |
| HTTP tracing | Tracing helper libraries | `net/http/httptrace` |
| TLS inspection | OpenSSL subprocess / helper packages | `crypto/tls` |
| X.509 validation | Certificate helper packages | `crypto/x509` |
| Proxy selection | `x/net/http/httpproxy` | `net/http.ProxyFromEnvironment` |
| Terminal tables | tablewriter / lipgloss | `text/tabwriter`, `fmt` |
| Bounded concurrency | `x/sync/semaphore` | Buffered channels + `sync.WaitGroup` |
| Semantic diff | go-cmp / diff packages | Typed comparison logic |
| JSON serialization | jsoniter / gjson | `encoding/json` with custom `DurationMs` formatting |
| UTF-16 snapshot decoding | `x/text` | `unicode/utf16`, `bytes` |
| Signal handling | Framework helpers | `os/signal`, `syscall` |

## DNS

`netwhy` contains a small DNS wire client for the record types required by the tool.

Implemented features:
* 12-byte header encoding and parsing (transaction ID, flags, counts)
* Dot-separated domain name (QNAME) label encoding
* Query support for A (IPv4) and AAAA (IPv6) records
* CNAME record parsing in answer sections
* RFC 1035 compressed-name decoding with offset tracking, loop detection, and a 32-jump depth cap
* Label length (`<= 63` bytes) and domain name length (`<= 255` bytes) validation
* UDP transport with timeout handling
* TC-bit truncation detection with automatic length-prefixed TCP fallback
* Query/response transaction ID verification

Boundaries:
* `netwhy` does not perform recursive resolution itself; DNS queries are sent to the configured resolver.
* DNSSEC validation is not implemented.
* EDNS(0) options are not negotiated.
* Record types outside A, AAAA, and CNAME are not decoded into typed fields.

This is intentionally a purpose-built DNS client, not a general-purpose DNS library.

## TLS

* Socket address pinning: Probes dial candidate IPs directly at the TCP layer while supplying the logical hostname in `tls.Config.ServerName` for SNI and certificate verification.
* Certificate capture: The initial diagnostic probe sets `InsecureSkipVerify: true` to complete handshakes on broken, expired, or self-signed servers so peer certificates can be captured and inspected.
* Manual verification: `crypto/x509` verifies hostname (`leaf.VerifyHostname`), validity periods (`leaf.NotBefore`, `leaf.NotAfter`), and trust chains (`leaf.Verify`).
* Handshake cancellation: Handshakes use `tlsConn.HandshakeContext(ctx)` for prompt cancellation when deadlines expire.

## HTTP

* Isolated transports: Each probe creates an `http.Transport` with `DisableKeepAlives: true` and calls `transport.CloseIdleConnections()` after use.
* Socket-level IP substitution: In direct mode, `http.Transport.DialContext` intercepts connections to the target hostname and dials the selected candidate IP.
* Redirect safety: Socket IP pinning applies only when dialing the original target host; redirects to different hostnames use standard DNS resolution.
* Proxy evaluation: `http.ProxyFromEnvironment` inspects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` variables for the target URL.
* HTTP tracing: `httptrace.ClientTrace` captures DNS done, TCP connect, TLS handshake, and first response byte events.
* Proxy TLS facts: In matrix mode, proxy path TLS metadata is extracted directly from `httptrace.ClientTrace.TLSHandshakeDone` rather than an out-of-band probe.

## Concurrency

TCP address probes use goroutines with a buffered channel as a semaphore and a `sync.WaitGroup`, with a maximum of eight concurrent attempts. Individual attempt results are collected through typed channels without shared state mutation.

## Snapshot diffing

Snapshots are compared semantically rather than textually:
* Resolved IPv4 and IPv6 address lists are deduplicated and sorted, making diffs order-independent.
* TLS certificate issuer, hostname validation state, HTTP response code, active proxy, and blocking layer are compared.
* Volatile timing measurements (such as TTFB) are omitted from semantic diffing.

## Output safety

`RedactHeaders` and `RedactURL` remove known credential-bearing headers, URL userinfo, and sensitive query parameters. Terminal output is sanitized before printing untrusted remote values.

## Verification

To verify that the project introduces no third-party dependencies:

```bash
go test ./...
go test -race ./...
go vet ./...
go list -m all
go mod graph
```

On the tested platform with standard Go tools:
* `go test ./...` and `go vet ./...` pass.
* `go list -m all` outputs only `github.com/skebzy/netwhy`.
* `go mod graph` confirms no third-party dependencies are required.
* `go test -race ./...` may require a C toolchain depending on platform and Go configuration.

See `deps-proof.txt` for the standalone dependency verification log.
