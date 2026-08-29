# netwhy

`netwhy` is a zero-third-party-dependency Go CLI for diagnosing endpoint connectivity. It checks DNS, TCP, TLS, and HTTP separately, then can repeat the connection through controlled path changes such as proxy bypass, IPv4-only, IPv6-only, or an alternate DNS resolver.

This is useful when the same endpoint works in one environment or path but fails in another.

## Core concept: differential path matrix

```bash
netwhy matrix https://api.example.com
```

Example output:

```text
Target: https://api.example.com

PATH               RESULT    HTTP    TLS ISSUER              DURATION
Application path   FAIL      -       -                       120ms
Direct             PASS      200     Example Issuing CA      43ms
IPv4 direct        PASS      200     Example Issuing CA      40ms
IPv6 direct        TIMEOUT   -       -                       3s

Observation:
  The connection succeeds when the configured proxy is bypassed.

Other differences:
  - IPv4 succeeds while IPv6 does not.
```

The rows are controlled variations of the same target. A difference between rows is usually more useful than an isolated failure because it narrows the part of the path that changed.

## Why it exists

A failed API call can come from DNS, TCP reachability, certificate validation, proxy configuration, IP-family differences, or the HTTP server itself. Tools such as `curl`, `dig`, and `openssl` are excellent for investigating individual parts, but correlating those results and repeating the same test under different path conditions takes manual work.

`netwhy` collects those observations in one run and can repeat the connection with specific variables changed.

## Build

Requires Go 1.23+:

```bash
go build -o netwhy .
```

On Windows:

```powershell
go build -o netwhy.exe .
```

Build without CGO and without embedded VCS/path metadata:

```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o netwhy .
```

## Basic usage

| Command | Purpose |
|---|---|
| `netwhy https://example.com` | Run DNS → TCP → TLS → HTTP diagnostics |
| `netwhy matrix https://example.com` | Compare network-path variations |
| `netwhy snapshot https://example.com` | Write a JSON snapshot |
| `netwhy diff before.json after.json` | Compare two snapshots |
| `netwhy --json https://example.com` | Emit structured JSON |
| `netwhy -v https://example.com` | Show chronological trace details |

Target formats include full URLs (`https://example.com/api`), host with port (`example.com:443`), IPv4 literals (`127.0.0.1:8080`), IPv6 literals (`[2001:db8::1]:443`), or bare hostnames (`example.com`).

## Standard diagnostic

Running `netwhy https://example.com` checks each layer sequentially:

```text
Target: https://example.com

LAYER   RESULT   DETAIL
DNS     PASS     2 IPv4, 2 IPv6
TCP     PASS     93.184.216.34:443
TLS     PASS     TLS 1.3, Example Issuing CA
HTTP    200      42ms total, 38ms TTFB

Result: endpoint responded successfully.
```

* **DNS:** Usable address records were returned for the target hostname.
* **TCP:** A TCP connection was established to at least one candidate address.
* **TLS:** The TLS handshake completed and hostname, validity period, and trust chain checks passed.
* **HTTP:** A valid HTTP response was received from the server.

## Matrix mode

Matrix mode runs controlled experiments against the target in parallel:

| Path | What changes |
|---|---|
| Application path | Uses normal HTTP behavior, including applicable environment proxy settings |
| Direct | Bypasses configured HTTP proxy (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) |
| IPv4 direct | Direct path restricted to IPv4 addresses |
| IPv6 direct | Direct path restricted to IPv6 addresses |
| Alternate resolver | Resolves through the selected DNS server and pins the direct socket connection to the resulting address |

Direct resolver-controlled paths preserve the original HTTP Host name and TLS SNI while changing the socket destination address. IP pinning applies only to the original target hostname; redirects to another hostname are resolved normally through system DNS.

## Alternate DNS resolver

To test whether the local resolver returns different results from a public or alternate nameserver:

```bash
netwhy --resolver 1.1.1.1 https://example.com
netwhy matrix --resolver 1.1.1.1 https://example.com
```

The alternate resolver is implemented directly with the Go standard library. The resulting address is used for the direct socket connection rather than resolving the hostname again through the system resolver.

The wire client supports:
* A and AAAA record queries
* CNAME response parsing
* UDP queries with timeout handling
* TC-bit truncation detection with automatic length-prefixed TCP fallback
* RFC 1035 compressed-name pointer decoding with jump limits and loop detection
* Transaction ID matching

## TLS inspection

The diagnostic TLS probe initially allows the handshake to complete without automatic certificate rejection so it can inspect certificates from endpoints presenting invalid or untrusted certificates. It then performs hostname, validity-period, and trust-chain verification explicitly with `crypto/x509`.

A successful handshake is not treated as a successful TLS validation unless those checks pass. When checking direct paths, the socket can connect to a resolved IP while the original hostname remains the SNI and certificate verification name.

## HTTP behavior

Any valid HTTP response, including 4xx and 5xx, counts as transport success. Those status codes indicate that DNS/TCP/TLS/HTTP transport completed and the server returned an application-layer response.

HTTP probing uses `net/http/httptrace` to record DNS lookup, TCP connect, TLS handshake, and Time to First Byte (TTFB) milestones. Transports are configured with `DisableKeepAlives: true` and closed after inspection to prevent connection reuse from affecting timing.

## Snapshots and diff

Snapshots capture diagnostic state to JSON for offline analysis or before/after comparisons:

```bash
netwhy snapshot https://example.com > before.json
# change network or proxy configuration
netwhy snapshot https://example.com > after.json

netwhy diff before.json after.json
```

The diff command semantically compares:
* Overall reachability status and first blocking layer
* Resolved IPv4 and IPv6 address sets (order-independent)
* TLS certificate issuer and hostname validation
* HTTP response status code
* Active proxy configuration

Volatile timing metrics are excluded from semantic diffing.

## JSON output and exit codes

Machine-readable JSON output is available via `--json`:

```bash
netwhy --json https://example.com
```

All duration fields in JSON are serialized in decimal milliseconds (`*_ms`).

### Exit codes

| Exit Code | Meaning |
|---|---|
| `0` | Endpoint reached or HTTP response received (including 4xx/5xx responses) |
| `1` | CLI argument syntax or invalid target error |
| `2` | DNS layer blocking failure |
| `3` | TCP layer blocking failure (all addresses timed out or refused) |
| `4` | TLS layer blocking failure (handshake failed or certificate invalid) |
| `5` | HTTP transport failure |
| `6` | Internal runtime error |

The `diff` subcommand returns exit code `0` when comparing valid snapshots, regardless of whether differences were found.

## Security and privacy

* Known sensitive request/response headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, etc.) are redacted in terminal and JSON outputs.
* Known sensitive query parameters (`token`, `api_key`, `secret`, `password`, `session_id`, etc.) are masked in URLs.
* Embedded URL proxy passwords (`http://user:pass@proxy:3128`) are masked as `http://***:***@proxy:3128`.
* Untrusted strings from remote banners or certificates are sanitized of ANSI escape sequences and non-printable control codes before terminal display. One-line output replaces newlines and tabs with spaces to prevent line forging.

## Zero third-party dependencies

`netwhy` uses no third-party Go modules and does not invoke external network utilities (such as `curl`, `dig`, `openssl`, or `ping`).

Standard library packages used include:
* CLI parsing: `flag`
* DNS: `net`, `encoding/binary`, `crypto/rand`
* TLS: `crypto/tls`, `crypto/x509`
* HTTP: `net/http`, `net/http/httptrace`
* Output: `text/tabwriter`, `encoding/json`
* Concurrency: `sync`, goroutines, channels
* Snapshot decoding: `unicode/utf16`, `bytes`

Running `go list -m all` shows only the project module `github.com/skebzy/netwhy`. See [STDLIB.md](STDLIB.md) for the complete dependency audit.

## Testing

The test suite covers:
* Target URI and address parsing
* DNS wire encoding, label boundaries, compression loop detection, and truncation TCP fallback
* Local UDP/TCP DNS fixtures
* TLS multi-certificate fixtures (trusted, hostname mismatch, expired, not yet valid, IP SAN)
* TLS context cancellation on stalled handshakes
* Alternate DNS socket address pinning and redirect host preservation
* Credential and header redaction
* Terminal escape sanitization
* Snapshot serialization, UTF-8 BOM, and UTF-16 LE/BE decoding
* JSON duration millisecond serialization

Run tests:

```bash
go test ./...
go vet ./...
```

Run DNS wire parser fuzzing:

```bash
go test -fuzz=FuzzDNSMessageParser -fuzztime=10s .
go test -fuzz=FuzzDNSNameDecoder -fuzztime=10s .
```

## Limitations

* **Userspace socket diagnostics:** Probing is performed via standard OS sockets. `netwhy` cannot perform raw packet capture or packet sniffing.
* **No ICMP ping or traceroute:** `netwhy` does not implement ICMP probing or traceroute, so it does not identify intermediate network hops.
* **No HTTP/3 (QUIC):** Probing is limited to HTTP/1.1 and HTTP/2 over TCP.
* **Inference boundaries:** A TCP timeout indicates that a connection could not be established before the deadline; it does not prove which firewall or router dropped the packet. Similarly, different TLS issuers across pathways indicate different certificate chains (e.g. proxy termination), not necessarily malicious interception.
* **Application health:** Receiving an HTTP response confirms transport connectivity and server responsiveness, not the functional correctness of backend application logic.

## Byte-identical build check

In the tested environment, two builds using the same Go toolchain and flags produced identical SHA-256 hashes.

* **Go Version:** `go1.26.7 windows/amd64`
* **OS / Arch:** Windows AMD64
* **CGO:** Disabled (`CGO_ENABLED=0`)
* **Build Command:** `CGO_ENABLED=0 go build -trimpath -buildvcs=false -o dist/build-a.exe .`

```text
4F2C6F86F15064056166F1B4190F358AF77F9C5F90A174E601EA521A40E1CD8F  dist/build-a.exe
4F2C6F86F15064056166F1B4190F358AF77F9C5F90A174E601EA521A40E1CD8F  dist/build-b.exe
```

## License

MIT License &mdash; Copyright &copy; 2026 netwhy contributors.
