package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode/utf16"
)

const (
	Version              = "0.1.0"
	CurrentSchemaVersion = 1
	CurrentToolVersion   = Version
)

const (
	ExitOK            = 0
	ExitInputError    = 1
	ExitDNSBlocking   = 2
	ExitTCPBlocking   = 3
	ExitTLSBlocking   = 4
	ExitHTTPTransport = 5
	ExitInternalError = 6
)

type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusPartial Status = "PARTIAL"
	StatusSkipped Status = "SKIPPED"
	StatusTimeout Status = "TIMEOUT"
	StatusRefused Status = "REFUSED"
)

type Layer string

const (
	LayerTarget      Layer = "TARGET"
	LayerEnvironment Layer = "ENVIRONMENT"
	LayerDNS         Layer = "DNS"
	LayerTCP         Layer = "TCP"
	LayerTLS         Layer = "TLS"
	LayerHTTP        Layer = "HTTP"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeAAAA  uint16 = 28
	TypeANY   uint16 = 255
)

const (
	ClassINET uint16 = 1
)

const (
	RCodeNoError        = 0
	RCodeFormatError    = 1
	RCodeServerFailure  = 2
	RCodeNameError      = 3
	RCodeNotImplemented = 4
	RCodeRefused        = 5
)

const maxConcurrentTCPAttempts = 8

// DurationMs wraps time.Duration so JSON marshaling outputs decimal milliseconds.
type DurationMs time.Duration

func (d DurationMs) Duration() time.Duration {
	return time.Duration(d)
}

func (d DurationMs) String() string {
	td := time.Duration(d)
	if td < time.Millisecond {
		return td.Round(100 * time.Microsecond).String()
	}
	return (td.Round(100 * time.Microsecond)).String()
}

func (d DurationMs) MarshalJSON() ([]byte, error) {
	ms := float64(time.Duration(d).Nanoseconds()) / 1e6
	str := strconv.FormatFloat(ms, 'f', 2, 64)
	str = strings.TrimRight(strings.TrimRight(str, "0"), ".")
	if str == "" || str == "-0" {
		str = "0"
	}
	return []byte(str), nil
}

func (d *DurationMs) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "null" || trimmed == "" {
		*d = 0
		return nil
	}

	var f float64
	if err := json.Unmarshal(b, &f); err == nil {
		*d = DurationMs(time.Duration(f * float64(time.Millisecond)))
		return nil
	}

	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration format %q: %w", s, err)
		}
		*d = DurationMs(dur)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s into DurationMs", trimmed)
}

var (
	ErrEmptyTarget       = errors.New("target cannot be empty")
	ErrInvalidTarget     = errors.New("invalid target format")
	ErrUnsupportedScheme = errors.New("unsupported URI scheme (only http and https are supported)")
	ErrInvalidPort       = errors.New("invalid port number (must be between 1 and 65535)")
	ErrMalformedPacket   = errors.New("malformed DNS packet")
	ErrTruncatedResponse = errors.New("truncated DNS response")
	ErrCompressionLoop   = errors.New("DNS name compression pointer loop detected")
	ErrMaxJumpsExceeded  = errors.New("DNS compression jump limit exceeded")
	ErrNameTooLong       = errors.New("DNS name exceeds maximum allowed length of 255 bytes")
	ErrLabelTooLong      = errors.New("DNS label exceeds maximum allowed length of 63 bytes")
	ErrZeroAnswers       = errors.New("no answers returned")
	ErrTimeout           = errors.New("DNS resolution timed out")
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Evidence       []string `json:"evidence"`
	PossibleCauses []string `json:"possible_causes,omitempty"`
}

type TraceEvent struct {
	Timestamp time.Time  `json:"timestamp"`
	Elapsed   DurationMs `json:"elapsed_ms"`
	Layer     Layer      `json:"layer"`
	Message   string     `json:"message"`
	Details   string     `json:"details,omitempty"`
}

type LayerReasoning struct {
	Layer       Layer    `json:"layer"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`
	Why         string   `json:"why"`
	RuledOut    []string `json:"ruled_out,omitempty"`
	NextActions []string `json:"next_actions,omitempty"`
}

type TargetInfo struct {
	Original string `json:"original"`
	Scheme   string `json:"scheme,omitempty"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Path     string `json:"path,omitempty"`
	Query    string `json:"query,omitempty"`
	IsIP     bool   `json:"is_ip"`
	IP       string `json:"ip,omitempty"`
	UseTLS   bool   `json:"use_tls"`
	UseHTTP  bool   `json:"use_http"`
}

type EnvironmentInfo struct {
	HTTPProxy      string `json:"http_proxy,omitempty"`
	HTTPSProxy     string `json:"https_proxy,omitempty"`
	AllProxy       string `json:"all_proxy,omitempty"`
	NoProxy        string `json:"no_proxy,omitempty"`
	SelectedProxy  string `json:"selected_proxy,omitempty"`
	HasProxyConfig bool   `json:"has_proxy_config"`
	ProxyForTarget bool   `json:"proxy_for_target"`
}

type DNSResult struct {
	Status       Status     `json:"status"`
	Resolver     string     `json:"resolver"`
	QueryName    string     `json:"query_name"`
	Duration     DurationMs `json:"duration_ms"`
	IPv4Addrs    []string   `json:"ipv4_addrs,omitempty"`
	IPv6Addrs    []string   `json:"ipv6_addrs,omitempty"`
	CNAMEs       []string   `json:"cnames,omitempty"`
	IsWireClient bool       `json:"is_wire_client"`
	Truncated    bool       `json:"truncated,omitempty"`
	RCode        string     `json:"rcode,omitempty"`
	Error        string     `json:"error,omitempty"`
}

type TCPAttempt struct {
	IP            string     `json:"ip"`
	Family        string     `json:"family"`
	Port          int        `json:"port"`
	Duration      DurationMs `json:"duration_ms"`
	Status        Status     `json:"status"`
	ErrorCategory string     `json:"error_category,omitempty"`
	Error         string     `json:"error,omitempty"`
}

type TCPResult struct {
	Status       Status       `json:"status"`
	Duration     DurationMs   `json:"duration_ms"`
	Attempts     []TCPAttempt `json:"attempts"`
	IPv4Success  bool         `json:"ipv4_success"`
	IPv6Success  bool         `json:"ipv6_success"`
	AnySuccess   bool         `json:"any_success"`
	ErrorSummary string       `json:"error_summary,omitempty"`
}

type TLSResult struct {
	Status            Status     `json:"status"`
	Connected         bool       `json:"connected"`
	HandshakeDuration DurationMs `json:"handshake_duration_ms"`
	DialedAddress     string     `json:"dialed_address,omitempty"`
	ServerName        string     `json:"server_name,omitempty"`
	Version           string     `json:"version,omitempty"`
	CipherSuite       string     `json:"cipher_suite,omitempty"`
	ALPN              string     `json:"alpn,omitempty"`
	LeafSubject       string     `json:"leaf_subject,omitempty"`
	LeafIssuer        string     `json:"leaf_issuer,omitempty"`
	DNSNames          []string   `json:"dns_names,omitempty"`
	IPAddresses       []string   `json:"ip_addresses,omitempty"`
	NotBefore         time.Time  `json:"not_before,omitempty"`
	NotAfter          time.Time  `json:"not_after,omitempty"`
	ChainLength       int        `json:"chain_length,omitempty"`
	ChainValid        bool       `json:"chain_valid"`
	HostnameValid     bool       `json:"hostname_valid"`
	ExpiryValid       bool       `json:"expiry_valid"`
	ValidationErrors  []string   `json:"validation_errors,omitempty"`
	Error             string     `json:"error,omitempty"`
}

type HTTPTiming struct {
	DNSDone DurationMs `json:"dns_done_ms,omitempty"`
	Connect DurationMs `json:"connect_ms,omitempty"`
	TLS     DurationMs `json:"tls_ms,omitempty"`
	TTFB    DurationMs `json:"ttfb_ms"`
	Total   DurationMs `json:"total_ms"`
}

type HTTPResult struct {
	Status        Status            `json:"status"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code,omitempty"`
	StatusText    string            `json:"status_text,omitempty"`
	Proto         string            `json:"proto,omitempty"`
	RemoteAddr    string            `json:"remote_addr,omitempty"`
	Redirects     []string          `json:"redirects,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Timings       HTTPTiming        `json:"timings"`
	UsedProxy     string            `json:"used_proxy,omitempty"`
	TLSVersion    string            `json:"tls_version,omitempty"`
	TLSCipher     string            `json:"tls_cipher,omitempty"`
	TLSALPN       string            `json:"tls_alpn,omitempty"`
	TLSIssuer     string            `json:"tls_issuer,omitempty"`
	TLSSubject    string            `json:"tls_subject,omitempty"`
	TLSServerName string            `json:"tls_server_name,omitempty"`
	Error         string            `json:"error,omitempty"`
}

type RunResult struct {
	Timestamp          time.Time        `json:"timestamp"`
	Target             TargetInfo       `json:"target"`
	Environment        EnvironmentInfo  `json:"environment"`
	DNS                *DNSResult       `json:"dns,omitempty"`
	TCP                *TCPResult       `json:"tcp,omitempty"`
	TLS                *TLSResult       `json:"tls,omitempty"`
	HTTP               *HTTPResult      `json:"http,omitempty"`
	OverallStatus      Status           `json:"overall_status"`
	FirstBlockingLayer Layer            `json:"first_blocking_layer,omitempty"`
	Findings           []Finding        `json:"findings"`
	Reasoning          []LayerReasoning `json:"reasoning,omitempty"`
	AnalysisSummary    string           `json:"analysis_summary,omitempty"`
	TraceEvents        []TraceEvent     `json:"trace_events,omitempty"`
	Verbose            bool             `json:"verbose,omitempty"`
}

type PathResult struct {
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Status        Status     `json:"status"`
	ConnectedIP   string     `json:"connected_ip,omitempty"`
	RemoteAddr    string     `json:"remote_addr,omitempty"`
	Resolver      string     `json:"resolver,omitempty"`
	UsedProxy     string     `json:"used_proxy,omitempty"`
	HTTPStatus    int        `json:"http_status,omitempty"`
	TLSVersion    string     `json:"tls_version,omitempty"`
	TLSIssuer     string     `json:"tls_issuer,omitempty"`
	BlockingLayer Layer      `json:"blocking_layer,omitempty"`
	Duration      DurationMs `json:"duration_ms"`
	Error         string     `json:"error,omitempty"`
	Run           *RunResult `json:"run,omitempty"`
}

type MatrixResult struct {
	Target                  TargetInfo      `json:"target"`
	Environment             EnvironmentInfo `json:"environment"`
	Paths                   []PathResult    `json:"paths"`
	ObservedDifferences     []string        `json:"observed_differences"`
	MostRelevantObservation string          `json:"most_relevant_observation"`
	Findings                []Finding       `json:"findings"`
	Verbose                 bool            `json:"verbose,omitempty"`
}

type Snapshot struct {
	SchemaVersion      int             `json:"schema_version"`
	ToolVersion        string          `json:"tool_version"`
	CapturedAt         time.Time       `json:"captured_at"`
	Target             TargetInfo      `json:"target"`
	Environment        EnvironmentInfo `json:"environment"`
	DNS                *DNSResult      `json:"dns,omitempty"`
	TCP                *TCPResult      `json:"tcp,omitempty"`
	TLS                *TLSResult      `json:"tls,omitempty"`
	HTTP               *HTTPResult     `json:"http,omitempty"`
	OverallStatus      Status          `json:"overall_status"`
	FirstBlockingLayer Layer           `json:"first_blocking_layer,omitempty"`
}

type SnapshotDiffItem struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
}

type SnapshotDiffResult struct {
	Target1     string             `json:"target1"`
	Target2     string             `json:"target2"`
	Timestamp1  time.Time          `json:"timestamp1"`
	Timestamp2  time.Time          `json:"timestamp2"`
	Differences []SnapshotDiffItem `json:"differences"`
	Summary     string             `json:"summary"`
}

type HTTPOptions struct {
	Method        string
	TargetURL     string
	TargetHost    string
	CustomDNSIP   string
	Timeout       time.Duration
	DialTimeout   time.Duration
	UseProxy      bool
	NetworkFamily string
}

type TLSOptions struct {
	ConnectHost string
	ServerName  string
	Port        int
	DialTimeout time.Duration
	RootCAs     *x509.CertPool
}

type Options struct {
	Target        string
	IPv4Only      bool
	IPv6Only      bool
	Resolver      string
	Method        string
	Timeout       time.Duration
	DialTimeout   time.Duration
	BypassProxy   bool
	ForcedNetwork string
	Verbose       bool
}

type MatrixOptions struct {
	Target      string
	Resolver    string
	Method      string
	Timeout     time.Duration
	DialTimeout time.Duration
}

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
	Text  string
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

type Resolver interface {
	Lookup(ctx context.Context, hostname string) (*DNSResult, error)
}

type SystemResolver struct {
	resolver *net.Resolver
}

type WireResolver struct {
	ResolverAddr string
}

// Redaction & terminal safety

var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"api-key":             true,
	"apikey":              true,
	"token":               true,
	"bearer":              true,
	"private-token":       true,
}

var sensitiveQueryParams = map[string]bool{
	"token":        true,
	"access_token": true,
	"api_key":      true,
	"apikey":       true,
	"secret":       true,
	"password":     true,
	"passwd":       true,
	"signature":    true,
	"sig":          true,
	"auth":         true,
	"key":          true,
	"session":      true,
	"session_id":   true,
	"sessionid":    true,
	"jwt":          true,
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)

// RedactHeaders returns a copy of headers with sensitive values masked.
func RedactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	clean := make(map[string]string, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if sensitiveHeaders[lk] {
			clean[k] = "[REDACTED]"
		} else {
			clean[k] = SanitizeTerminalOneLine(v)
		}
	}
	return clean
}

// RedactURL masks sensitive query parameters and URL userinfo credentials.
func RedactURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return SanitizeTerminalOneLine(rawURL)
	}

	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			u.User = url.UserPassword("***", "***")
		} else if u.User.Username() != "" {
			u.User = url.User("***")
		}
	}

	if u.RawQuery != "" {
		q := u.Query()
		modified := false
		for param := range q {
			lp := strings.ToLower(strings.TrimSpace(param))
			if sensitiveQueryParams[lp] {
				q.Set(param, "[REDACTED]")
				modified = true
			}
		}
		if modified {
			u.RawQuery = q.Encode()
		}
	}

	res := u.String()
	res = strings.ReplaceAll(res, "%2A%2A%2A", "***")
	res = strings.ReplaceAll(res, "%2a%2a%2a", "***")
	res = strings.ReplaceAll(res, "%5BREDACTED%5D", "[REDACTED]")
	res = strings.ReplaceAll(res, "%5bredacted%5d", "[REDACTED]")

	return SanitizeTerminalOneLine(res)
}

// SanitizeTerminalOneLine strips ANSI escapes and replaces newlines/tabs with spaces to prevent line forging in table cells.
func SanitizeTerminalOneLine(s string) string {
	if s == "" {
		return ""
	}
	cleaned := ansiRegex.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\r' || r == '\n' || r == '\t' {
			sb.WriteRune(' ')
		} else if r >= 0x20 && r != 0x7F {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

// SanitizeTerminal strips ANSI escapes and control codes while preserving newlines.
func SanitizeTerminal(s string) string {
	if s == "" {
		return ""
	}
	cleaned := ansiRegex.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(cleaned))
	for _, r := range cleaned {
		if (r >= 0x20 && r != 0x7F) || r == '\t' || r == '\n' || r == '\r' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// Target parsing

func ParseTarget(raw string) (TargetInfo, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TargetInfo{}, ErrEmptyTarget
	}

	sanitized := SanitizeTerminalOneLine(trimmed)

	var info TargetInfo
	info.Original = RedactURL(sanitized)

	if idx := strings.Index(sanitized, "://"); idx != -1 {
		scheme := strings.ToLower(sanitized[:idx])
		if scheme != "http" && scheme != "https" {
			return TargetInfo{}, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
		}

		u, err := url.Parse(sanitized)
		if err != nil {
			return TargetInfo{}, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
		}

		info.Scheme = scheme
		info.UseHTTP = true
		info.UseTLS = (scheme == "https")
		info.Path = u.Path
		info.Query = u.RawQuery

		host := u.Hostname()
		portStr := u.Port()

		if portStr == "" {
			if info.Scheme == "https" {
				info.Port = 443
			} else {
				info.Port = 80
			}
		} else {
			p, err := strconv.Atoi(portStr)
			if err != nil || p <= 0 || p > 65535 {
				return TargetInfo{}, ErrInvalidPort
			}
			info.Port = p
		}

		info.Hostname = strings.ToLower(strings.TrimSuffix(host, "."))
	} else {
		var hostPort string
		var pathPart string
		if slashIdx := strings.Index(sanitized, "/"); slashIdx != -1 {
			hostPort = sanitized[:slashIdx]
			pathPart = sanitized[slashIdx:]
		} else {
			hostPort = sanitized
		}

		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			if strings.Count(hostPort, ":") > 1 {
				host = strings.Trim(hostPort, "[]")
				portStr = ""
			} else {
				host = hostPort
				portStr = ""
			}
		}

		host = strings.Trim(host, "[]")
		host = strings.TrimSuffix(host, ".")
		info.Hostname = strings.ToLower(host)
		info.Path = pathPart

		if portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err != nil || p <= 0 || p > 65535 {
				return TargetInfo{}, ErrInvalidPort
			}
			info.Port = p
			if p == 443 || p == 8443 {
				info.UseTLS = true
				info.UseHTTP = true
				info.Scheme = "https"
			} else if p == 80 || p == 8080 {
				info.UseTLS = false
				info.UseHTTP = true
				info.Scheme = "http"
			} else {
				info.UseTLS = false
				info.UseHTTP = true
				info.Scheme = "http"
			}
		} else {
			info.Port = 80
			info.Scheme = "http"
			info.UseHTTP = true
			info.UseTLS = false
		}
	}

	if parsedIP := net.ParseIP(info.Hostname); parsedIP != nil {
		info.IsIP = true
		info.IP = parsedIP.String()
	}

	if info.Hostname == "" {
		return TargetInfo{}, ErrInvalidTarget
	}

	return info, nil
}

// DNS wire client

func RCodeString(rcode int) string {
	switch rcode {
	case RCodeNoError:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func EncodeQuestion(name string, qtype uint16) ([]byte, uint16, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		idBytes[0] = 0x12
		idBytes[1] = 0x34
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD = 1 (Recursion Desired)
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCount = 1

	encodedName, err := EncodeDomainName(name)
	if err != nil {
		return nil, 0, err
	}
	buf = append(buf, encodedName...)

	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], ClassINET)
	buf = append(buf, tail[:]...)

	return buf, id, nil
}

func EncodeDomainName(domain string) ([]byte, error) {
	trimmed := strings.Trim(domain, ".")
	if trimmed == "" {
		return []byte{0}, nil
	}
	labels := strings.Split(trimmed, ".")
	var buf []byte
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("%w: label %q has length %d", ErrLabelTooLong, label, len(label))
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	if len(buf) > 255 {
		return nil, ErrNameTooLong
	}
	return buf, nil
}

// DecodeDomainName parses a domain name from packet starting at offset. It tracks visited
// pointer offsets to prevent compression loops and caps pointer jumps at 32.
func DecodeDomainName(packet []byte, startOffset int) (string, int, error) {
	if startOffset < 0 || startOffset >= len(packet) {
		return "", 0, ErrMalformedPacket
	}

	offset := startOffset
	visited := make(map[int]bool)
	jumpCount := 0
	const maxJumps = 32
	bytesConsumed := 0
	jumping := false

	var labels []string
	totalNameLen := 0

	for {
		if offset >= len(packet) {
			return "", 0, ErrMalformedPacket
		}

		length := int(packet[offset])

		if length == 0 {
			if !jumping {
				bytesConsumed++
			}
			break
		}

		if (length & 0xC0) == 0xC0 {
			if offset+1 >= len(packet) {
				return "", 0, ErrMalformedPacket
			}
			ptr := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3FFF)

			if !jumping {
				bytesConsumed += 2
			}
			jumping = true

			if ptr >= len(packet) {
				return "", 0, ErrMalformedPacket
			}
			if visited[ptr] {
				return "", 0, ErrCompressionLoop
			}
			visited[ptr] = true
			jumpCount++
			if jumpCount > maxJumps {
				return "", 0, ErrMaxJumpsExceeded
			}

			offset = ptr
			continue
		}

		if (length & 0xC0) != 0 {
			return "", 0, ErrMalformedPacket
		}

		offset++
		if !jumping {
			bytesConsumed++
		}

		if offset+length > len(packet) {
			return "", 0, ErrMalformedPacket
		}

		labelBytes := packet[offset : offset+length]
		labels = append(labels, string(labelBytes))
		totalNameLen += length + 1
		if totalNameLen > 255 {
			return "", 0, ErrNameTooLong
		}

		offset += length
		if !jumping {
			bytesConsumed += length
		}
	}

	return strings.Join(labels, "."), bytesConsumed, nil
}

func ParseDNSMessage(packet []byte) (*Message, error) {
	if len(packet) < 12 {
		return nil, ErrMalformedPacket
	}

	msg := &Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(packet[0:2]),
			Flags:   binary.BigEndian.Uint16(packet[2:4]),
			QDCount: binary.BigEndian.Uint16(packet[4:6]),
			ANCount: binary.BigEndian.Uint16(packet[6:8]),
			NSCount: binary.BigEndian.Uint16(packet[8:10]),
			ARCount: binary.BigEndian.Uint16(packet[10:12]),
		},
	}

	offset := 12

	for i := 0; i < int(msg.Header.QDCount); i++ {
		name, consumed, err := DecodeDomainName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset += consumed
		if offset+4 > len(packet) {
			return nil, ErrMalformedPacket
		}
		qtype := binary.BigEndian.Uint16(packet[offset : offset+2])
		qclass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4

		msg.Questions = append(msg.Questions, Question{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	parseRRSection := func(count int) ([]ResourceRecord, error) {
		var records []ResourceRecord
		for i := 0; i < count; i++ {
			if offset >= len(packet) {
				return nil, ErrMalformedPacket
			}
			name, consumed, err := DecodeDomainName(packet, offset)
			if err != nil {
				return nil, err
			}
			offset += consumed
			if offset+10 > len(packet) {
				return nil, ErrMalformedPacket
			}

			rrType := binary.BigEndian.Uint16(packet[offset : offset+2])
			rrClass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			ttl := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
			rdLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
			offset += 10

			if offset+rdLength > len(packet) {
				return nil, ErrMalformedPacket
			}

			rdata := packet[offset : offset+rdLength]
			var textVal string

			switch rrType {
			case TypeA:
				if rdLength == 4 {
					textVal = net.IP(rdata).String()
				}
			case TypeAAAA:
				if rdLength == 16 {
					textVal = net.IP(rdata).String()
				}
			case TypeCNAME:
				cname, _, err := DecodeDomainName(packet, offset)
				if err == nil {
					textVal = cname
				}
			}

			records = append(records, ResourceRecord{
				Name:  name,
				Type:  rrType,
				Class: rrClass,
				TTL:   ttl,
				Data:  rdata,
				Text:  textVal,
			})
			offset += rdLength
		}
		return records, nil
	}

	var err error
	if msg.Answers, err = parseRRSection(int(msg.Header.ANCount)); err != nil {
		return nil, err
	}
	if msg.Authorities, err = parseRRSection(int(msg.Header.NSCount)); err != nil {
		return nil, err
	}
	if msg.Additionals, err = parseRRSection(int(msg.Header.ARCount)); err != nil {
		return nil, err
	}

	return msg, nil
}

// WireQuery sends a DNS query over UDP, falling back to 2-byte length-prefixed TCP if the TC bit is set.
func WireQuery(ctx context.Context, resolverAddr, hostname string, qtype uint16) (*Message, time.Duration, error) {
	if !strings.Contains(resolverAddr, ":") {
		resolverAddr = net.JoinHostPort(resolverAddr, "53")
	}

	reqPacket, queryID, err := EncodeQuestion(hostname, qtype)
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", resolverAddr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(reqPacket); err != nil {
		return nil, 0, err
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	duration := time.Since(start)
	if err != nil {
		return nil, duration, err
	}

	msg, err := ParseDNSMessage(respBuf[:n])
	if err != nil {
		return nil, duration, err
	}

	if msg.Header.ID != queryID {
		return nil, duration, fmt.Errorf("mismatched transaction ID: expected %d, got %d", queryID, msg.Header.ID)
	}

	isTruncated := (msg.Header.Flags & 0x0200) != 0
	if isTruncated {
		tcpStart := time.Now()
		tcpConn, tcpErr := d.DialContext(ctx, "tcp", resolverAddr)
		if tcpErr != nil {
			return msg, duration, nil
		}
		defer tcpConn.Close()

		if deadline, ok := ctx.Deadline(); ok {
			_ = tcpConn.SetDeadline(deadline)
		}

		tcpReq := make([]byte, 2+len(reqPacket))
		binary.BigEndian.PutUint16(tcpReq[0:2], uint16(len(reqPacket)))
		copy(tcpReq[2:], reqPacket)

		if _, err := tcpConn.Write(tcpReq); err != nil {
			return msg, duration, nil
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(tcpConn, lenBuf[:]); err != nil {
			return msg, duration, nil
		}
		respLen := int(binary.BigEndian.Uint16(lenBuf[:]))

		tcpResp := make([]byte, respLen)
		if _, err := io.ReadFull(tcpConn, tcpResp); err != nil {
			return msg, duration, nil
		}

		tcpDuration := time.Since(tcpStart)
		tcpMsg, err := ParseDNSMessage(tcpResp)
		if err == nil {
			return tcpMsg, duration + tcpDuration, nil
		}
	}

	return msg, duration, nil
}

func NewSystemResolver() *SystemResolver {
	return &SystemResolver{
		resolver: net.DefaultResolver,
	}
}

func (s *SystemResolver) Lookup(ctx context.Context, hostname string) (*DNSResult, error) {
	result := &DNSResult{
		Status:    StatusPass,
		Resolver:  "system",
		QueryName: hostname,
	}

	start := time.Now()

	var wg sync.WaitGroup
	var ipv4Addrs, ipv6Addrs []string
	var ipv4Err, ipv6Err, cnameErr error
	var cname string

	wg.Add(3)

	go func() {
		defer wg.Done()
		ips, err := s.resolver.LookupIP(ctx, "ip4", hostname)
		if err != nil {
			ipv4Err = err
			return
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				ipv4Addrs = append(ipv4Addrs, v4.String())
			}
		}
	}()

	go func() {
		defer wg.Done()
		ips, err := s.resolver.LookupIP(ctx, "ip6", hostname)
		if err != nil {
			ipv6Err = err
			return
		}
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		}
	}()

	go func() {
		defer wg.Done()
		cn, err := s.resolver.LookupCNAME(ctx, hostname)
		if err != nil {
			cnameErr = err
			return
		}
		cname = strings.TrimSuffix(cn, ".")
	}()

	wg.Wait()
	result.Duration = DurationMs(time.Since(start))
	result.IPv4Addrs = sortedUnique(ipv4Addrs)
	result.IPv6Addrs = sortedUnique(ipv6Addrs)
	if cname != "" && cname != strings.TrimSuffix(hostname, ".") {
		result.CNAMEs = []string{cname}
	}

	if len(result.IPv4Addrs) == 0 && len(result.IPv6Addrs) == 0 {
		result.Status = StatusFail
		if ipv4Err != nil && ipv6Err != nil {
			result.Error = fmt.Sprintf("IPv4: %v; IPv6: %v", ipv4Err, ipv6Err)
		} else if ipv4Err != nil {
			result.Error = fmt.Sprintf("IPv4: %v", ipv4Err)
		} else if ipv6Err != nil {
			result.Error = fmt.Sprintf("IPv6: %v", ipv6Err)
		} else if cnameErr != nil {
			result.Error = fmt.Sprintf("lookup error: %v", cnameErr)
		} else {
			result.Error = "no address records found"
		}
		return result, fmt.Errorf("DNS resolution failed: %s", result.Error)
	}

	return result, nil
}

func NewWireResolver(serverAddr string) *WireResolver {
	return &WireResolver{
		ResolverAddr: serverAddr,
	}
}

func (w *WireResolver) Lookup(ctx context.Context, hostname string) (*DNSResult, error) {
	result := &DNSResult{
		Status:       StatusPass,
		Resolver:     w.ResolverAddr,
		QueryName:    hostname,
		IsWireClient: true,
	}

	start := time.Now()

	var wg sync.WaitGroup
	var ipv4Addrs, ipv6Addrs, cnames []string
	var msgA, msgAAAA *Message
	var errA, errAAAA error

	wg.Add(2)

	go func() {
		defer wg.Done()
		msgA, _, errA = WireQuery(ctx, w.ResolverAddr, hostname, TypeA)
		if errA == nil && msgA != nil {
			for _, ans := range msgA.Answers {
				if ans.Type == TypeA && ans.Text != "" {
					ipv4Addrs = append(ipv4Addrs, ans.Text)
				} else if ans.Type == TypeCNAME && ans.Text != "" {
					cnames = append(cnames, ans.Text)
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		msgAAAA, _, errAAAA = WireQuery(ctx, w.ResolverAddr, hostname, TypeAAAA)
		if errAAAA == nil && msgAAAA != nil {
			for _, ans := range msgAAAA.Answers {
				if ans.Type == TypeAAAA && ans.Text != "" {
					ipv6Addrs = append(ipv6Addrs, ans.Text)
				} else if ans.Type == TypeCNAME && ans.Text != "" {
					cnames = append(cnames, ans.Text)
				}
			}
		}
	}()

	wg.Wait()

	result.Duration = DurationMs(time.Since(start))
	result.IPv4Addrs = sortedUnique(ipv4Addrs)
	result.IPv6Addrs = sortedUnique(ipv6Addrs)
	result.CNAMEs = sortedUnique(cnames)

	if msgA != nil {
		rcode := int(msgA.Header.Flags & 0x000F)
		result.RCode = RCodeString(rcode)
		result.Truncated = (msgA.Header.Flags & 0x0200) != 0
	} else if msgAAAA != nil {
		rcode := int(msgAAAA.Header.Flags & 0x000F)
		result.RCode = RCodeString(rcode)
		result.Truncated = (msgAAAA.Header.Flags & 0x0200) != 0
	}

	if len(result.IPv4Addrs) == 0 && len(result.IPv6Addrs) == 0 {
		result.Status = StatusFail
		if errA != nil && errAAAA != nil {
			result.Error = fmt.Sprintf("A query: %v; AAAA query: %v", errA, errAAAA)
		} else if errA != nil {
			result.Error = fmt.Sprintf("A query: %v", errA)
		} else if errAAAA != nil {
			result.Error = fmt.Sprintf("AAAA query: %v", errAAAA)
		} else if result.RCode != "NOERROR" && result.RCode != "" {
			result.Error = fmt.Sprintf("resolver returned %s", result.RCode)
		} else {
			result.Error = "no address records returned by resolver"
		}
		return result, fmt.Errorf("DNS resolution failed: %s", result.Error)
	}

	return result, nil
}

// Environment & proxy inspection

func InspectEnvironment(targetURL *url.URL) EnvironmentInfo {
	env := EnvironmentInfo{}

	getEnv := func(upper, lower string) string {
		if v := os.Getenv(upper); v != "" {
			return v
		}
		return os.Getenv(lower)
	}

	env.HTTPProxy = RedactURL(getEnv("HTTP_PROXY", "http_proxy"))
	env.HTTPSProxy = RedactURL(getEnv("HTTPS_PROXY", "https_proxy"))
	env.AllProxy = RedactURL(getEnv("ALL_PROXY", "all_proxy"))
	env.NoProxy = getEnv("NO_PROXY", "no_proxy")

	env.HasProxyConfig = env.HTTPProxy != "" || env.HTTPSProxy != "" || env.AllProxy != ""

	if targetURL != nil {
		req := &http.Request{URL: targetURL}
		proxyURL, err := http.ProxyFromEnvironment(req)
		if err == nil && proxyURL != nil {
			env.SelectedProxy = RedactURL(proxyURL.String())
			env.ProxyForTarget = true
		}
	}

	return env
}

// TCP probing

func ClassifyTCPError(err error) string {
	if err == nil {
		return ""
	}
	if os.IsTimeout(err) || errorsContains(err, "timeout", "deadline exceeded", "timed out", "context deadline exceeded") {
		return "timeout"
	}
	if errorsContains(err, "refused", "actively refused", "connection reset") {
		return "refused"
	}
	if errorsContains(err, "unreachable", "no route to host", "network is unreachable", "host is unreachable") {
		return "unreachable"
	}
	if errorsContains(err, "permission denied", "access is denied", "operation not permitted") {
		return "permission"
	}
	return "other"
}

func errorsContains(err error, substrings ...string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range substrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

func ProbeTCP(ctx context.Context, ips []string, port int, dialTimeout time.Duration) *TCPResult {
	if len(ips) == 0 {
		return &TCPResult{
			Status:       StatusFail,
			ErrorSummary: "no IP addresses available to connect",
		}
	}

	result := &TCPResult{
		Attempts: make([]TCPAttempt, 0, len(ips)),
	}

	start := time.Now()
	sem := make(chan struct{}, maxConcurrentTCPAttempts)
	resultsChan := make(chan TCPAttempt, len(ips))

	var wg sync.WaitGroup

	for _, ipStr := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			attempt := probeSingleTCP(ctx, ip, port, dialTimeout)
			resultsChan <- attempt
		}(ipStr)
	}

	wg.Wait()
	close(resultsChan)

	result.Duration = DurationMs(time.Since(start))

	var rawAttempts []TCPAttempt
	for attempt := range resultsChan {
		rawAttempts = append(rawAttempts, attempt)
	}

	// Deterministic sorting of attempts: family (ipv4 first), IP, port.
	sort.Slice(rawAttempts, func(i, j int) bool {
		if rawAttempts[i].Family != rawAttempts[j].Family {
			return rawAttempts[i].Family < rawAttempts[j].Family
		}
		if rawAttempts[i].IP != rawAttempts[j].IP {
			return rawAttempts[i].IP < rawAttempts[j].IP
		}
		return rawAttempts[i].Port < rawAttempts[j].Port
	})

	result.Attempts = rawAttempts

	var hasV4Success, hasV4Fail bool
	var hasV6Success, hasV6Fail bool
	var allTimeouts = true
	var allRefused = true

	for _, attempt := range result.Attempts {
		isV4 := attempt.Family == "ipv4"

		if attempt.Status == StatusPass {
			result.AnySuccess = true
			allTimeouts = false
			allRefused = false
			if isV4 {
				hasV4Success = true
			} else {
				hasV6Success = true
			}
		} else {
			if attempt.ErrorCategory != "timeout" {
				allTimeouts = false
			}
			if attempt.ErrorCategory != "refused" {
				allRefused = false
			}
			if isV4 {
				hasV4Fail = true
			} else {
				hasV6Fail = true
			}
		}
	}

	result.IPv4Success = hasV4Success
	result.IPv6Success = hasV6Success

	if result.AnySuccess {
		if (hasV4Success && hasV6Fail) || (hasV6Success && hasV4Fail) {
			result.Status = StatusPartial
		} else {
			result.Status = StatusPass
		}
	} else {
		if allTimeouts {
			result.Status = StatusTimeout
			result.ErrorSummary = "all connection attempts timed out"
		} else if allRefused {
			result.Status = StatusRefused
			result.ErrorSummary = "all connection attempts were refused"
		} else {
			result.Status = StatusFail
			result.ErrorSummary = "all connection attempts failed"
		}
	}

	return result
}

func probeSingleTCP(ctx context.Context, ipStr string, port int, dialTimeout time.Duration) TCPAttempt {
	parsedIP := net.ParseIP(ipStr)
	family := "ipv4"
	if parsedIP != nil && parsedIP.To4() == nil {
		family = "ipv6"
	}

	addr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", port))
	attempt := TCPAttempt{
		IP:     ipStr,
		Family: family,
		Port:   port,
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer
	start := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	attempt.Duration = DurationMs(time.Since(start))

	if err != nil {
		attempt.ErrorCategory = ClassifyTCPError(err)
		attempt.Error = SanitizeTerminalOneLine(err.Error())
		if attempt.ErrorCategory == "timeout" {
			attempt.Status = StatusTimeout
		} else if attempt.ErrorCategory == "refused" {
			attempt.Status = StatusRefused
		} else {
			attempt.Status = StatusFail
		}
		return attempt
	}
	defer conn.Close()

	attempt.Status = StatusPass
	return attempt
}

// TLS inspection

func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// ProbeTLS connects to opts.ConnectHost at the socket layer while using opts.ServerName
// for SNI and certificate verification.
func ProbeTLS(ctx context.Context, opts TLSOptions) *TLSResult {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 3 * time.Second
	}
	if opts.ServerName == "" {
		opts.ServerName = opts.ConnectHost
	}

	dialHost := opts.ConnectHost
	if dialHost == "" {
		dialHost = opts.ServerName
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", opts.Port))

	result := &TLSResult{
		ServerName:    opts.ServerName,
		DialedAddress: addr,
	}

	// Complete handshake without automatic certificate rejection so the presented
	// chain can still be captured from broken endpoints. Verification is performed below.
	tlsConfig := &tls.Config{
		ServerName:         opts.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if opts.RootCAs != nil {
		tlsConfig.RootCAs = opts.RootCAs
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()

	var dialer net.Dialer
	start := time.Now()

	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		result.Connected = false
		result.Status = StatusFail
		result.Error = SanitizeTerminalOneLine(err.Error())
		result.HandshakeDuration = DurationMs(time.Since(start))
		return result
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	handshakeErr := tlsConn.HandshakeContext(dialCtx)
	result.HandshakeDuration = DurationMs(time.Since(start))

	if handshakeErr != nil {
		result.Connected = false
		result.Status = StatusFail
		result.Error = SanitizeTerminalOneLine(handshakeErr.Error())
		return result
	}

	result.Connected = true
	state := tlsConn.ConnectionState()

	result.Version = TLSVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.ALPN = state.NegotiatedProtocol

	if len(state.PeerCertificates) == 0 {
		result.Status = StatusFail
		result.Error = "no peer certificates presented"
		return result
	}

	result.ChainLength = len(state.PeerCertificates)
	leaf := state.PeerCertificates[0]

	result.LeafSubject = SanitizeTerminalOneLine(leaf.Subject.String())
	result.LeafIssuer = SanitizeTerminalOneLine(leaf.Issuer.CommonName)
	if result.LeafIssuer == "" {
		result.LeafIssuer = SanitizeTerminalOneLine(leaf.Issuer.String())
	}
	result.NotBefore = leaf.NotBefore
	result.NotAfter = leaf.NotAfter

	for _, name := range leaf.DNSNames {
		result.DNSNames = append(result.DNSNames, SanitizeTerminalOneLine(name))
	}
	for _, ip := range leaf.IPAddresses {
		result.IPAddresses = append(result.IPAddresses, ip.String())
	}

	now := time.Now()
	var validationErrors []string

	if now.Before(leaf.NotBefore) {
		result.ExpiryValid = false
		validationErrors = append(validationErrors, fmt.Sprintf("certificate is not yet valid (valid from %s)", leaf.NotBefore.Format(time.RFC3339)))
	} else if now.After(leaf.NotAfter) {
		result.ExpiryValid = false
		validationErrors = append(validationErrors, fmt.Sprintf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339)))
	} else {
		result.ExpiryValid = true
	}

	if err := leaf.VerifyHostname(opts.ServerName); err != nil {
		result.HostnameValid = false
		var hErr x509.HostnameError
		if errors.As(err, &hErr) {
			validationErrors = append(validationErrors, fmt.Sprintf("hostname mismatch: certificate does not match %q", opts.ServerName))
		} else {
			validationErrors = append(validationErrors, fmt.Sprintf("hostname validation: %v", err))
		}
	} else {
		result.HostnameValid = true
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	verifyOpts := x509.VerifyOptions{
		DNSName:       opts.ServerName,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	if opts.RootCAs != nil {
		verifyOpts.Roots = opts.RootCAs
	}

	if _, err := leaf.Verify(verifyOpts); err != nil {
		result.ChainValid = false
		var unkAuthErr x509.UnknownAuthorityError
		var certInvErr x509.CertificateInvalidError
		if errors.As(err, &unkAuthErr) {
			validationErrors = append(validationErrors, "certificate signed by unknown authority")
		} else if errors.As(err, &certInvErr) {
			validationErrors = append(validationErrors, fmt.Sprintf("certificate invalid: %v", certInvErr))
		} else {
			errMsg := SanitizeTerminalOneLine(err.Error())
			if !strings.Contains(errMsg, "certificate is valid for") {
				validationErrors = append(validationErrors, fmt.Sprintf("chain verification failed: %s", errMsg))
			}
		}
	} else {
		result.ChainValid = true
	}

	result.ValidationErrors = validationErrors

	if result.ExpiryValid && result.HostnameValid && result.ChainValid {
		result.Status = StatusPass
	} else {
		result.Status = StatusFail
		if len(validationErrors) > 0 {
			result.Error = strings.Join(validationErrors, "; ")
		} else {
			result.Error = "certificate validation failed"
		}
	}

	return result
}

// HTTP probing

func ProbeHTTP(ctx context.Context, opts HTTPOptions) *HTTPResult {
	if opts.Method == "" {
		opts.Method = "HEAD"
	}
	opts.Method = strings.ToUpper(strings.TrimSpace(opts.Method))

	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 3 * time.Second
	}
	if opts.NetworkFamily == "" {
		opts.NetworkFamily = "tcp"
	}

	result := &HTTPResult{
		Method: opts.Method,
		URL:    RedactURL(opts.TargetURL),
	}

	parsedURL, err := url.Parse(opts.TargetURL)
	if err != nil {
		result.Status = StatusFail
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}

	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var (
		dnsStart, dnsDone   time.Time
		connStart, connDone time.Time
		tlsStart, tlsDone   time.Time
		reqStart            time.Time
		gotFirstByte        time.Time
		resolvedRemoteAddr  string
		observedTLSState    *tls.ConnectionState
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			if dnsStart.IsZero() {
				dnsStart = time.Now()
			}
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if dnsDone.IsZero() {
				dnsDone = time.Now()
			}
		},
		ConnectStart: func(network, addr string) {
			if connStart.IsZero() {
				connStart = time.Now()
			}
		},
		ConnectDone: func(network, addr string, err error) {
			if connDone.IsZero() {
				connDone = time.Now()
			}
			if err == nil && resolvedRemoteAddr == "" {
				resolvedRemoteAddr = addr
			}
		},
		TLSHandshakeStart: func() {
			if tlsStart.IsZero() {
				tlsStart = time.Now()
			}
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if tlsDone.IsZero() {
				tlsDone = time.Now()
			}
			if err == nil {
				st := state
				observedTLSState = &st
			}
		},
		GotFirstResponseByte: func() {
			if gotFirstByte.IsZero() {
				gotFirstByte = time.Now()
			}
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), opts.Method, opts.TargetURL, nil)
	if err != nil {
		result.Status = StatusFail
		result.Error = fmt.Sprintf("failed to build HTTP request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", fmt.Sprintf("netwhy/%s", Version))
	req.Header.Set("Accept", "*/*")

	dialer := &net.Dialer{
		Timeout:   opts.DialTimeout,
		KeepAlive: 0,
	}

	targetHostToPin := opts.TargetHost
	if targetHostToPin == "" {
		targetHostToPin = parsedURL.Hostname()
	}

	transport := &http.Transport{
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: opts.Timeout,
		TLSHandshakeTimeout:   opts.DialTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			netFam := opts.NetworkFamily
			if netFam == "" {
				netFam = "tcp"
			}

			dialAddr := addr
			// Pin socket destination only when dialing the original target host.
			// Redirects to other hosts resolve normally through system DNS.
			if opts.CustomDNSIP != "" && !opts.UseProxy {
				host, port, splitErr := net.SplitHostPort(addr)
				if splitErr == nil && strings.EqualFold(host, targetHostToPin) {
					dialAddr = net.JoinHostPort(opts.CustomDNSIP, port)
				}
			}

			return dialer.DialContext(ctx, netFam, dialAddr)
		},
	}
	defer transport.CloseIdleConnections()

	if opts.UseProxy {
		transport.Proxy = http.ProxyFromEnvironment
		if proxyURL, err := http.ProxyFromEnvironment(req); err == nil && proxyURL != nil {
			result.UsedProxy = RedactURL(proxyURL.String())
		}
	} else {
		transport.Proxy = nil
	}

	var redirects []string
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			redirects = append(redirects, RedactURL(req.URL.String()))
			return nil
		},
	}

	reqStart = time.Now()
	resp, err := client.Do(req)
	totalDuration := time.Since(reqStart)

	result.Timings.Total = DurationMs(totalDuration)
	if !gotFirstByte.IsZero() {
		result.Timings.TTFB = DurationMs(gotFirstByte.Sub(reqStart))
	} else {
		result.Timings.TTFB = DurationMs(totalDuration)
	}

	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		result.Timings.DNSDone = DurationMs(dnsDone.Sub(dnsStart))
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		result.Timings.Connect = DurationMs(connDone.Sub(connStart))
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		result.Timings.TLS = DurationMs(tlsDone.Sub(tlsStart))
	}

	result.RemoteAddr = resolvedRemoteAddr
	result.Redirects = redirects

	if observedTLSState != nil {
		result.TLSVersion = TLSVersionName(observedTLSState.Version)
		result.TLSCipher = tls.CipherSuiteName(observedTLSState.CipherSuite)
		result.TLSALPN = observedTLSState.NegotiatedProtocol
		result.TLSServerName = observedTLSState.ServerName
		if len(observedTLSState.PeerCertificates) > 0 {
			leaf := observedTLSState.PeerCertificates[0]
			result.TLSSubject = SanitizeTerminalOneLine(leaf.Subject.String())
			issuer := leaf.Issuer.CommonName
			if issuer == "" {
				issuer = leaf.Issuer.String()
			}
			result.TLSIssuer = SanitizeTerminalOneLine(issuer)
		}
	}

	if err != nil {
		result.Status = StatusFail
		result.Error = SanitizeTerminalOneLine(err.Error())
		return result
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.Proto = resp.Proto

	rawHeaders := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		rawHeaders[k] = strings.Join(vals, ", ")
	}
	result.Headers = RedactHeaders(rawHeaders)

	result.Status = StatusPass
	return result
}

// Explanation & reasoning

func Explain(res *RunResult) []Finding {
	findings, _, _ := ExplainWithReasoning(res)
	return findings
}

// ExplainWithReasoning derives findings and per-layer explanations from a run result.
func ExplainWithReasoning(res *RunResult) ([]Finding, []LayerReasoning, string) {
	if res == nil {
		return nil, nil, ""
	}

	var findings []Finding
	var reasoning []LayerReasoning
	var summaryParts []string

	if res.DNS != nil {
		dnsReas := LayerReasoning{
			Layer:  LayerDNS,
			Status: res.DNS.Status,
		}

		if res.DNS.Status == StatusSkipped {
			dnsReas.Summary = "DNS lookup was bypassed for direct IP target."
			dnsReas.Why = fmt.Sprintf("Target %q is an IP literal.", res.DNS.QueryName)
			dnsReas.RuledOut = []string{"Name resolution failure"}
		} else if res.DNS.Status == StatusPass {
			v4Count := len(res.DNS.IPv4Addrs)
			v6Count := len(res.DNS.IPv6Addrs)
			dnsReas.Summary = fmt.Sprintf("Resolved %d IPv4, %d IPv6 address records.", v4Count, v6Count)
			dnsReas.Why = fmt.Sprintf("The selected resolver %q returned address records for %q.", res.DNS.Resolver, res.DNS.QueryName)
			dnsReas.RuledOut = []string{
				"Failure to obtain address records from this resolver during this run",
			}
		} else {
			dnsReas.Summary = fmt.Sprintf("DNS resolution failed for %q.", res.DNS.QueryName)
			dnsReas.Why = fmt.Sprintf("Resolver %q returned error: %s.", res.DNS.Resolver, res.DNS.Error)
			dnsReas.NextActions = []string{
				"Verify hostname spelling or DNS zone configuration",
				"Test resolution with an alternate resolver: netwhy --resolver 1.1.1.1 <target>",
			}

			evidence := []string{
				fmt.Sprintf("Query Name: %s", res.DNS.QueryName),
				fmt.Sprintf("Resolver: %s", res.DNS.Resolver),
			}
			if res.DNS.Error != "" {
				evidence = append(evidence, fmt.Sprintf("Error: %s", res.DNS.Error))
			}
			if res.DNS.RCode != "" {
				evidence = append(evidence, fmt.Sprintf("RCODE: %s", res.DNS.RCode))
			}

			var possibleCauses []string
			if res.DNS.RCode == "NXDOMAIN" {
				possibleCauses = append(possibleCauses, "Domain name does not exist in DNS (NXDOMAIN)")
			} else if res.DNS.RCode == "SERVFAIL" {
				possibleCauses = append(possibleCauses, "Nameserver encountered an internal failure or DNSSEC validation error (SERVFAIL)")
			} else if res.DNS.RCode == "REFUSED" {
				possibleCauses = append(possibleCauses, "Resolver refused the query (REFUSED)")
			} else {
				possibleCauses = append(possibleCauses,
					"Domain has no active A or AAAA records",
					"Resolver unreachable or timed out",
					"Port 53 UDP/TCP traffic blocked on network",
				)
			}

			findings = append(findings, Finding{
				Severity:       SeverityCritical,
				Title:          "DNS Resolution Failed",
				Evidence:       evidence,
				PossibleCauses: possibleCauses,
			})
			summaryParts = append(summaryParts, "Connection blocked at DNS layer (no address records returned).")
		}
		reasoning = append(reasoning, dnsReas)
	}

	if res.TCP != nil {
		tcpReas := LayerReasoning{
			Layer:  LayerTCP,
			Status: res.TCP.Status,
		}

		if res.TCP.Status == StatusPass {
			tcpReas.Summary = fmt.Sprintf("TCP connection established successfully on port %d.", res.Target.Port)
			tcpReas.Why = fmt.Sprintf("TCP handshake completed successfully to destination on port %d.", res.Target.Port)
			tcpReas.RuledOut = []string{
				"Port closed on tested address",
				"Routing gateway failure",
			}
		} else if res.TCP.Status == StatusPartial {
			tcpReas.Summary = "Partial TCP reachability: IPv4 succeeded while IPv6 failed or timed out."
			tcpReas.Why = "Target resolved both address families, but connection only succeeded over IPv4."
			tcpReas.NextActions = []string{
				"Test IPv4 exclusively: netwhy --ipv4 <target>",
				"Inspect local IPv6 routing and upstream connectivity",
			}

			var evidence []string
			for _, a := range res.TCP.Attempts {
				statusStr := string(a.Status)
				if a.Error != "" {
					statusStr = fmt.Sprintf("%s (%s)", statusStr, a.Error)
				}
				evidence = append(evidence, fmt.Sprintf("%s (%s): %s in %v", a.Family, a.IP, statusStr, a.Duration))
			}

			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Title:    "IPv6 Connectivity Difference",
				Evidence: evidence,
				PossibleCauses: []string{
					"Local network or ISP has broken or unrouted IPv6 connectivity",
					"Remote server advertises AAAA records but is not listening on IPv6 port",
					"Upstream firewall filtering IPv6 traffic",
				},
			})
			summaryParts = append(summaryParts, "Dual-stack reachability difference: IPv4 succeeded while IPv6 failed.")
		} else if res.TCP.Status == StatusTimeout {
			tcpReas.Summary = fmt.Sprintf("TCP connections timed out on port %d across tested addresses.", res.Target.Port)
			tcpReas.Why = "Connection attempts did not complete before the dial deadline."
			tcpReas.RuledOut = []string{
				"Active rejection by host (no RST packet returned)",
			}
			tcpReas.NextActions = []string{
				fmt.Sprintf("Check firewall/security group rules for destination port %d", res.Target.Port),
				"Test path matrix to inspect proxy reachability: netwhy matrix <target>",
			}

			var evidence []string
			for _, a := range res.TCP.Attempts {
				evidence = append(evidence, fmt.Sprintf("%s (%s:%d): TIMEOUT (%s) in %v", a.Family, a.IP, a.Port, a.Error, a.Duration))
			}

			findings = append(findings, Finding{
				Severity: SeverityCritical,
				Title:    "TCP Connection Timed Out",
				Evidence: evidence,
				PossibleCauses: []string{
					"Firewall or security group dropping TCP connection attempts",
					"Routing failure or unreachable destination host",
					"Target host offline or non-responsive",
				},
			})
			summaryParts = append(summaryParts, fmt.Sprintf("Connection blocked at TCP layer (timed out on port %d).", res.Target.Port))
		} else if res.TCP.Status == StatusRefused {
			tcpReas.Summary = fmt.Sprintf("TCP connection actively refused on port %d.", res.Target.Port)
			tcpReas.Why = "Target host actively rejected the connection attempt."
			tcpReas.RuledOut = []string{
				"Silent packet drop by network firewall",
			}
			tcpReas.NextActions = []string{
				fmt.Sprintf("Verify that service daemon is listening on port %d", res.Target.Port),
			}

			var evidence []string
			for _, a := range res.TCP.Attempts {
				evidence = append(evidence, fmt.Sprintf("%s (%s:%d): REFUSED (%s) in %v", a.Family, a.IP, a.Port, a.Error, a.Duration))
			}

			findings = append(findings, Finding{
				Severity: SeverityCritical,
				Title:    "TCP Connection Refused",
				Evidence: evidence,
				PossibleCauses: []string{
					"No service currently listening on specified port",
					"Service crashed or is stopped",
					"Local host firewall actively rejecting connection",
				},
			})
			summaryParts = append(summaryParts, fmt.Sprintf("Connection blocked at TCP layer (connection refused on port %d).", res.Target.Port))
		} else {
			tcpReas.Summary = "TCP connection attempts failed."
			tcpReas.Why = res.TCP.ErrorSummary
		}

		reasoning = append(reasoning, tcpReas)
	}

	if res.TLS != nil && res.Target.UseTLS {
		tlsReas := LayerReasoning{
			Layer:  LayerTLS,
			Status: res.TLS.Status,
		}

		if !res.TLS.Connected {
			tlsReas.Summary = "TLS handshake failed to complete."
			tlsReas.Why = fmt.Sprintf("TLS handshake failed: %s", res.TLS.Error)
			tlsReas.NextActions = []string{
				"Check whether destination port expects plain HTTP instead of HTTPS",
			}
			findings = append(findings, Finding{
				Severity: SeverityCritical,
				Title:    "TLS Handshake Failed",
				Evidence: []string{
					fmt.Sprintf("Target: %s:%d", res.TLS.ServerName, res.Target.Port),
					fmt.Sprintf("Error: %s", res.TLS.Error),
				},
				PossibleCauses: []string{
					"Target port is serving plain TCP or HTTP instead of TLS",
					"TLS protocol version or cipher suite incompatibility",
					"Remote server closed connection during handshake",
				},
			})
			summaryParts = append(summaryParts, "Connection blocked at TLS layer (handshake failed).")
		} else if res.TLS.Status == StatusPass {
			tlsReas.Summary = fmt.Sprintf("TLS %s handshake succeeded (%s, ALPN: %s).", res.TLS.Version, res.TLS.CipherSuite, res.TLS.ALPN)
			tlsReas.Why = fmt.Sprintf("Certificate is valid until %s, issued by %q, matching hostname %q.", res.TLS.NotAfter.Format("2006-01-02"), res.TLS.LeafIssuer, res.TLS.ServerName)
			tlsReas.RuledOut = []string{
				"Expired or not yet valid certificates",
				"Hostname / SNI mismatch",
				"Untrusted certificate authority",
			}
		} else {
			tlsReas.Summary = "TLS handshake completed, but certificate validation failed."
			tlsReas.Why = strings.Join(res.TLS.ValidationErrors, "; ")

			if !res.TLS.HostnameValid {
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Title:    "TLS Certificate Hostname Mismatch",
					Evidence: []string{
						fmt.Sprintf("Requested Hostname: %s", res.TLS.ServerName),
						fmt.Sprintf("Presented Subject: %s", res.TLS.LeafSubject),
						fmt.Sprintf("Presented DNS SANs: %s", strings.Join(res.TLS.DNSNames, ", ")),
					},
					PossibleCauses: []string{
						"Server returned certificate for a different domain",
						"Connecting by IP literal to a server without matching IP SAN",
						"Traffic redirected to unexpected destination",
					},
				})
			}
			if !res.TLS.ExpiryValid {
				title := "TLS Certificate Expired"
				now := time.Now()
				if now.Before(res.TLS.NotBefore) {
					title = "TLS Certificate Not Yet Valid"
				}
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Title:    title,
					Evidence: []string{
						fmt.Sprintf("Validity Window: %s to %s", res.TLS.NotBefore.Format(time.RFC3339), res.TLS.NotAfter.Format(time.RFC3339)),
					},
					PossibleCauses: []string{
						"Certificate validity period has expired or not started",
						"Local system clock is inaccurate",
					},
				})
			}
			if !res.TLS.ChainValid {
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Title:    "TLS Certificate Chain Verification Failed",
					Evidence: []string{
						fmt.Sprintf("Issuer: %s", res.TLS.LeafIssuer),
						fmt.Sprintf("Chain Length: %d", res.TLS.ChainLength),
						fmt.Sprintf("Validation Errors: %s", strings.Join(res.TLS.ValidationErrors, "; ")),
					},
					PossibleCauses: []string{
						"Certificate is self-signed or signed by untrusted authority",
						"Intermediate CA certificate missing from server bundle",
						"Inspection proxy re-signing certificate with custom internal root",
					},
				})
			}
			summaryParts = append(summaryParts, "Connection blocked at TLS layer (certificate validation failed).")
		}
		reasoning = append(reasoning, tlsReas)
	}

	if res.HTTP != nil && res.Target.UseHTTP {
		httpReas := LayerReasoning{
			Layer:  LayerHTTP,
			Status: res.HTTP.Status,
		}

		if res.HTTP.Status == StatusPass {
			if res.HTTP.StatusCode >= 200 && res.HTTP.StatusCode < 400 {
				httpReas.Summary = fmt.Sprintf("HTTP %s returned status %d %s.", res.HTTP.Method, res.HTTP.StatusCode, res.HTTP.StatusText)
				httpReas.Why = "An HTTP response was received successfully."
			} else {
				httpReas.Summary = fmt.Sprintf("HTTP server responded with application status %d %s.", res.HTTP.StatusCode, res.HTTP.StatusText)
				httpReas.Why = "The HTTP transport completed and the server returned an application-layer status."
				httpReas.RuledOut = []string{
					"Network transport failure",
				}
				findings = append(findings, Finding{
					Severity: SeverityInfo,
					Title:    fmt.Sprintf("HTTP Server Responded (%d %s)", res.HTTP.StatusCode, res.HTTP.StatusText),
					Evidence: []string{
						fmt.Sprintf("Status: %d %s", res.HTTP.StatusCode, res.HTTP.StatusText),
						fmt.Sprintf("Proto: %s", res.HTTP.Proto),
						fmt.Sprintf("Remote Address: %s", res.HTTP.RemoteAddr),
						fmt.Sprintf("TTFB: %v", res.HTTP.Timings.TTFB),
					},
					PossibleCauses: []string{
						"Endpoint reached; status code represents application response",
					},
				})
			}
		} else {
			httpReas.Summary = fmt.Sprintf("HTTP transaction failed: %s", res.HTTP.Error)
			httpReas.Why = "Connection closed or timed out during HTTP exchange."
			findings = append(findings, Finding{
				Severity: SeverityCritical,
				Title:    "HTTP Transport Failure",
				Evidence: []string{
					fmt.Sprintf("URL: %s", res.HTTP.URL),
					fmt.Sprintf("Method: %s", res.HTTP.Method),
					fmt.Sprintf("Error: %s", res.HTTP.Error),
				},
				PossibleCauses: []string{
					"HTTP connection dropped or timed out before response headers received",
					"Configured proxy rejected request or tunnel",
					"Server closed connection during request transmission",
				},
			})
			summaryParts = append(summaryParts, "Connection blocked at HTTP layer (transport failure).")
		}
		reasoning = append(reasoning, httpReas)
	}

	if res.Environment.ProxyForTarget && res.Environment.SelectedProxy != "" {
		findings = append(findings, Finding{
			Severity: SeverityInfo,
			Title:    "HTTP Proxy Active",
			Evidence: []string{
				fmt.Sprintf("Target routed via proxy: %s", res.Environment.SelectedProxy),
			},
			PossibleCauses: []string{
				"Environment variable (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY) configured for target",
			},
		})
	}

	summary := strings.Join(summaryParts, " ")
	if summary == "" {
		summary = "All evaluated layers completed successfully. Endpoint is reachable."
	}

	return findings, reasoning, summary
}

func ExplainMatrix(matrix *MatrixResult) (differences []string, primaryObs string, findings []Finding) {
	if matrix == nil || len(matrix.Paths) == 0 {
		return nil, "", nil
	}

	var pathApp, pathDirect, pathIPv4, pathIPv6, pathResolver *PathResult

	for i := range matrix.Paths {
		p := &matrix.Paths[i]
		switch p.Name {
		case "Application path":
			pathApp = p
		case "Direct":
			pathDirect = p
		case "IPv4 direct":
			pathIPv4 = p
		case "IPv6 direct":
			pathIPv6 = p
		case "Alternate resolver":
			pathResolver = p
		}
	}

	if pathApp != nil && pathDirect != nil {
		if pathApp.Status != pathDirect.Status {
			if pathApp.Status == StatusFail && pathDirect.Status == StatusPass {
				differences = append(differences, "Direct connection succeeds, but application path (via proxy) fails.")
				if matrix.Environment.ProxyForTarget {
					primaryObs = "The configured HTTP proxy changes the connection outcome."
					findings = append(findings, Finding{
						Severity: SeverityCritical,
						Title:    "Proxy Path Changes Connection Outcome",
						Evidence: []string{
							fmt.Sprintf("Application path: %s (%s)", pathApp.Status, pathApp.Error),
							fmt.Sprintf("Direct path: %s", pathDirect.Status),
							fmt.Sprintf("Configured Proxy: %s", matrix.Environment.SelectedProxy),
						},
						PossibleCauses: []string{
							"Configured HTTP proxy unreachable or rejecting CONNECT tunnel",
							"Proxy credentials invalid or expired",
							"Target host may need to be added to NO_PROXY",
						},
					})
				}
			} else if pathApp.Status == StatusPass && pathDirect.Status == StatusFail {
				differences = append(differences, "Application path succeeds, but direct connection fails.")
				primaryObs = "Endpoint reachable via application path but not through direct connection."
				findings = append(findings, Finding{
					Severity: SeverityInfo,
					Title:    "Endpoint Reachable via Proxy but not Direct Path",
					Evidence: []string{
						fmt.Sprintf("Application path: %s", pathApp.Status),
						fmt.Sprintf("Direct path: %s (%s)", pathDirect.Status, pathDirect.Error),
					},
					PossibleCauses: []string{
						"Target host is inside an internal perimeter only accessible via proxy",
					},
				})
			}
		}

		if pathApp.TLSIssuer != "" && pathDirect.TLSIssuer != "" && pathApp.TLSIssuer != pathDirect.TLSIssuer {
			diffMsg := fmt.Sprintf("Proxy path presents certificate issuer %q while direct path presents %q.", pathApp.TLSIssuer, pathDirect.TLSIssuer)
			differences = append(differences, diffMsg)
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Title:    "TLS Certificate Issuer Divergence",
				Evidence: []string{
					fmt.Sprintf("Application path TLS Issuer: %s", pathApp.TLSIssuer),
					fmt.Sprintf("Direct path TLS Issuer: %s", pathDirect.TLSIssuer),
				},
				PossibleCauses: []string{
					"Proxy is performing SSL/TLS inspection or termination",
				},
			})
		}
	}

	if pathIPv4 != nil && pathIPv6 != nil {
		if pathIPv4.Status == StatusPass && (pathIPv6.Status == StatusFail || pathIPv6.Status == StatusTimeout) {
			differences = append(differences, fmt.Sprintf("IPv4 direct connection succeeded, but IPv6 direct connection failed or timed out (%s).", pathIPv6.Status))
			if primaryObs == "" {
				primaryObs = "IPv6 direct connection failed while IPv4 direct connection succeeded."
			}
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Title:    "IPv6 Direct Path Failure",
				Evidence: []string{
					fmt.Sprintf("IPv4 Direct: %s in %v", pathIPv4.Status, pathIPv4.Duration),
					fmt.Sprintf("IPv6 Direct: %s in %v (%s)", pathIPv6.Status, pathIPv6.Duration, pathIPv6.Error),
				},
				PossibleCauses: []string{
					"Local network or ISP has broken IPv6 routing",
					"Target server is not listening on IPv6 or firewall is dropping IPv6 packets",
				},
			})
		} else if (pathIPv4.Status == StatusFail || pathIPv4.Status == StatusTimeout) && pathIPv6.Status == StatusPass {
			differences = append(differences, fmt.Sprintf("IPv6 direct connection succeeded, but IPv4 direct connection failed (%s).", pathIPv4.Status))
			if primaryObs == "" {
				primaryObs = "IPv4 direct connection failed while IPv6 direct connection succeeded."
			}
		}
	}

	if pathResolver != nil && pathDirect != nil {
		if pathResolver.Status != pathDirect.Status {
			differences = append(differences, fmt.Sprintf("Alternate DNS resolver outcome (%s) differs from system resolver outcome (%s).", pathResolver.Status, pathDirect.Status))
		}
		if pathResolver.Run != nil && pathDirect.Run != nil && pathResolver.Run.DNS != nil && pathDirect.Run.DNS != nil {
			v4Direct := strings.Join(pathDirect.Run.DNS.IPv4Addrs, ", ")
			v4Alt := strings.Join(pathResolver.Run.DNS.IPv4Addrs, ", ")
			if v4Direct != v4Alt && v4Direct != "" && v4Alt != "" {
				differences = append(differences, fmt.Sprintf("Alternate resolver returned IPv4 [%s] while system resolver returned [%s].", v4Alt, v4Direct))
			}
		}
	}

	if primaryObs == "" {
		if len(differences) > 0 {
			primaryObs = differences[0]
		} else {
			allPass := true
			for _, p := range matrix.Paths {
				if p.Status != StatusPass {
					allPass = false
					break
				}
			}
			if allPass {
				primaryObs = "All comparative network pathways reached the destination successfully."
			} else {
				primaryObs = "Target is unreachable across all evaluated pathways."
			}
		}
	}

	return differences, primaryObs, findings
}

// Probing & matrix execution

// Run probes the target through DNS, TCP, TLS, and HTTP as applicable.
func Run(ctx context.Context, opts Options) (*RunResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 3 * time.Second
	}
	if opts.Method == "" {
		opts.Method = "HEAD"
	}

	startOverall := time.Now()

	targetInfo, err := ParseTarget(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("target parse error: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	result := &RunResult{
		Timestamp:     startOverall.UTC(),
		Target:        targetInfo,
		OverallStatus: StatusPass,
		Verbose:       opts.Verbose,
	}

	logEvent := func(layer Layer, msg, details string) {
		result.TraceEvents = append(result.TraceEvents, TraceEvent{
			Timestamp: time.Now().UTC(),
			Elapsed:   DurationMs(time.Since(startOverall)),
			Layer:     layer,
			Message:   msg,
			Details:   details,
		})
	}

	logEvent(LayerTarget, "Target parsed",
		fmt.Sprintf("Host=%s, Port=%d, Scheme=%s, TLS=%t, HTTP=%t, IP=%t",
			targetInfo.Hostname, targetInfo.Port, targetInfo.Scheme, targetInfo.UseTLS, targetInfo.UseHTTP, targetInfo.IsIP))

	var parsedTargetURL *url.URL
	if targetInfo.UseHTTP {
		scheme := targetInfo.Scheme
		if scheme == "" {
			if targetInfo.UseTLS {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		rawURL := fmt.Sprintf("%s://%s:%d%s", scheme, targetInfo.Hostname, targetInfo.Port, targetInfo.Path)
		if targetInfo.Query != "" {
			rawURL += "?" + targetInfo.Query
		}
		parsedTargetURL, _ = url.Parse(rawURL)
	}

	result.Environment = InspectEnvironment(parsedTargetURL)
	if result.Environment.HasProxyConfig {
		if result.Environment.ProxyForTarget && !opts.BypassProxy {
			logEvent(LayerEnvironment, "Proxy active for target",
				fmt.Sprintf("Target will route via %s", result.Environment.SelectedProxy))
		} else if opts.BypassProxy {
			logEvent(LayerEnvironment, "Proxy bypassed", "Direct connection mode forced")
		} else {
			logEvent(LayerEnvironment, "Proxy configured but target excluded (NO_PROXY)", "")
		}
	} else {
		logEvent(LayerEnvironment, "No proxy configured", "Connecting directly")
	}

	var candidateIPs []string

	if targetInfo.IsIP {
		logEvent(LayerDNS, "DNS resolution skipped", fmt.Sprintf("Target %s is an IP literal", targetInfo.IP))
		parsedIP := net.ParseIP(targetInfo.IP)
		dnsRes := &DNSResult{
			Status:    StatusSkipped,
			Resolver:  "none (direct IP)",
			QueryName: targetInfo.IP,
		}
		if parsedIP != nil && parsedIP.To4() != nil {
			dnsRes.IPv4Addrs = []string{targetInfo.IP}
			if !opts.IPv6Only {
				candidateIPs = append(candidateIPs, targetInfo.IP)
			}
		} else if parsedIP != nil {
			dnsRes.IPv6Addrs = []string{targetInfo.IP}
			if !opts.IPv4Only {
				candidateIPs = append(candidateIPs, targetInfo.IP)
			}
		}
		result.DNS = dnsRes
	} else {
		var resolver Resolver
		resolverName := "system"
		if opts.Resolver != "" {
			resolver = NewWireResolver(opts.Resolver)
			resolverName = fmt.Sprintf("wire client (%s)", opts.Resolver)
		} else {
			resolver = NewSystemResolver()
		}

		logEvent(LayerDNS, fmt.Sprintf("Resolving via %s", resolverName),
			fmt.Sprintf("Querying hostname %q", targetInfo.Hostname))

		dnsRes, err := resolver.Lookup(runCtx, targetInfo.Hostname)
		result.DNS = dnsRes

		if err != nil || dnsRes.Status == StatusFail {
			logEvent(LayerDNS, "DNS resolution failed", fmt.Sprintf("Error: %s (Duration: %v)", dnsRes.Error, dnsRes.Duration))
			result.OverallStatus = StatusFail
			result.FirstBlockingLayer = LayerDNS
			result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
			return result, nil
		}

		logEvent(LayerDNS, "DNS resolution succeeded",
			fmt.Sprintf("Resolved %d IPv4 (%s), %d IPv6 (%s) in %v",
				len(dnsRes.IPv4Addrs), strings.Join(dnsRes.IPv4Addrs, ", "),
				len(dnsRes.IPv6Addrs), strings.Join(dnsRes.IPv6Addrs, ", "),
				dnsRes.Duration))

		if !opts.IPv6Only {
			candidateIPs = append(candidateIPs, dnsRes.IPv4Addrs...)
		}
		if !opts.IPv4Only {
			candidateIPs = append(candidateIPs, dnsRes.IPv6Addrs...)
		}

		if len(candidateIPs) == 0 {
			logEvent(LayerDNS, "No usable IP addresses matching filter criteria", "")
			result.OverallStatus = StatusFail
			result.FirstBlockingLayer = LayerDNS
			result.DNS.Status = StatusFail
			if opts.IPv4Only {
				result.DNS.Error = "no IPv4 (A) records available for IPv4-only filter"
			} else if opts.IPv6Only {
				result.DNS.Error = "no IPv6 (AAAA) records available for IPv6-only filter"
			}
			result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
			return result, nil
		}
	}

	logEvent(LayerTCP, fmt.Sprintf("Probing TCP to %d IP(s) on port %d", len(candidateIPs), targetInfo.Port),
		fmt.Sprintf("Dial timeout: %v", opts.DialTimeout))

	tcpRes := ProbeTCP(runCtx, candidateIPs, targetInfo.Port, opts.DialTimeout)
	result.TCP = tcpRes

	var selectedIP string
	for _, a := range tcpRes.Attempts {
		if a.Status == StatusPass {
			if selectedIP == "" {
				selectedIP = a.IP
			}
			logEvent(LayerTCP, fmt.Sprintf("TCP connected to %s (%s:%d)", a.Family, a.IP, a.Port), fmt.Sprintf("Duration: %v", a.Duration))
		} else {
			logEvent(LayerTCP, fmt.Sprintf("TCP failed to %s (%s:%d)", a.Family, a.IP, a.Port), fmt.Sprintf("Status: %s, Error: %s in %v", a.Status, a.Error, a.Duration))
		}
	}

	if !tcpRes.AnySuccess {
		logEvent(LayerTCP, "All TCP connection attempts failed", tcpRes.ErrorSummary)
		result.OverallStatus = tcpRes.Status
		result.FirstBlockingLayer = LayerTCP
		result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
		return result, nil
	}

	if selectedIP == "" && len(candidateIPs) > 0 {
		selectedIP = candidateIPs[0]
	}

	if targetInfo.UseTLS {
		connectHost := selectedIP
		if connectHost == "" {
			connectHost = targetInfo.Hostname
		}

		logEvent(LayerTLS, fmt.Sprintf("Starting TLS probe to %s (SNI: %q)", connectHost, targetInfo.Hostname),
			fmt.Sprintf("Port: %d, Timeout: %v", targetInfo.Port, opts.DialTimeout))

		tlsRes := ProbeTLS(runCtx, TLSOptions{
			ConnectHost: connectHost,
			ServerName:  targetInfo.Hostname,
			Port:        targetInfo.Port,
			DialTimeout: opts.DialTimeout,
		})
		result.TLS = tlsRes

		if !tlsRes.Connected {
			logEvent(LayerTLS, "TLS handshake failed", tlsRes.Error)
			result.OverallStatus = StatusFail
			result.FirstBlockingLayer = LayerTLS
			if !targetInfo.UseHTTP {
				result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
				return result, nil
			}
		} else {
			logEvent(LayerTLS, fmt.Sprintf("TLS handshake succeeded (%s, %s, ALPN: %s)", tlsRes.Version, tlsRes.CipherSuite, tlsRes.ALPN),
				fmt.Sprintf("Duration: %v, Issuer: %q", tlsRes.HandshakeDuration, tlsRes.LeafIssuer))

			if !tlsRes.HostnameValid || !tlsRes.ExpiryValid || !tlsRes.ChainValid {
				logEvent(LayerTLS, "TLS certificate verification failed", strings.Join(tlsRes.ValidationErrors, "; "))
				result.OverallStatus = StatusFail
				result.FirstBlockingLayer = LayerTLS
				if !targetInfo.UseHTTP {
					result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
					return result, nil
				}
			} else {
				logEvent(LayerTLS, "TLS certificate verification passed",
					fmt.Sprintf("Valid until: %s", tlsRes.NotAfter.Format("2006-01-02 15:04:05 UTC")))
			}
		}
	}

	if targetInfo.UseHTTP && parsedTargetURL != nil {
		netFam := opts.ForcedNetwork
		if netFam == "" {
			if opts.IPv4Only {
				netFam = "tcp4"
			} else if opts.IPv6Only {
				netFam = "tcp6"
			} else {
				netFam = "tcp"
			}
		}

		useProxy := !opts.BypassProxy && result.Environment.ProxyForTarget
		logEvent(LayerHTTP, fmt.Sprintf("Executing HTTP %s request to %s", opts.Method, parsedTargetURL.String()),
			fmt.Sprintf("Network: %s, Proxy active: %t", netFam, useProxy))

		customIP := ""
		if !useProxy && !targetInfo.IsIP {
			customIP = selectedIP
		}

		httpOpts := HTTPOptions{
			Method:        opts.Method,
			TargetURL:     parsedTargetURL.String(),
			TargetHost:    targetInfo.Hostname,
			CustomDNSIP:   customIP,
			Timeout:       opts.Timeout,
			DialTimeout:   opts.DialTimeout,
			UseProxy:      !opts.BypassProxy,
			NetworkFamily: netFam,
		}

		httpRes := ProbeHTTP(runCtx, httpOpts)
		result.HTTP = httpRes

		if httpRes.Status == StatusFail {
			logEvent(LayerHTTP, "HTTP request failed", httpRes.Error)
			if result.OverallStatus == StatusPass {
				result.OverallStatus = StatusFail
				if result.FirstBlockingLayer == "" {
					result.FirstBlockingLayer = LayerHTTP
				}
			}
		} else {
			logEvent(LayerHTTP, fmt.Sprintf("HTTP response received (%d %s, %s)", httpRes.StatusCode, httpRes.StatusText, httpRes.Proto),
				fmt.Sprintf("Remote: %s, TTFB: %v, Total: %v", httpRes.RemoteAddr, httpRes.Timings.TTFB, httpRes.Timings.Total))
		}
	}

	if result.FirstBlockingLayer == "" && result.TCP != nil && result.TCP.Status == StatusPartial {
		result.OverallStatus = StatusPartial
	}

	result.Findings, result.Reasoning, result.AnalysisSummary = ExplainWithReasoning(result)
	return result, nil
}

func RunMatrix(ctx context.Context, opts MatrixOptions) (*MatrixResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 3 * time.Second
	}
	if opts.Method == "" {
		opts.Method = "HEAD"
	}

	targetInfo, err := ParseTarget(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("target parse error: %w", err)
	}

	matrix := &MatrixResult{
		Target: targetInfo,
	}

	appRun, _ := Run(ctx, Options{
		Target:      opts.Target,
		BypassProxy: false,
		Method:      opts.Method,
		Timeout:     opts.Timeout,
		DialTimeout: opts.DialTimeout,
	})
	if appRun != nil {
		matrix.Environment = appRun.Environment
	}
	matrix.Paths = append(matrix.Paths, buildPathResult("Application path", "Uses system resolver and configured environment proxy", appRun, true))

	directRun, _ := Run(ctx, Options{
		Target:      opts.Target,
		BypassProxy: true,
		Method:      opts.Method,
		Timeout:     opts.Timeout,
		DialTimeout: opts.DialTimeout,
	})
	matrix.Paths = append(matrix.Paths, buildPathResult("Direct", "Direct connection with environment proxy bypassed", directRun, false))

	ipv4Run, _ := Run(ctx, Options{
		Target:        opts.Target,
		BypassProxy:   true,
		IPv4Only:      true,
		ForcedNetwork: "tcp4",
		Method:        opts.Method,
		Timeout:       opts.Timeout,
		DialTimeout:   opts.DialTimeout,
	})
	matrix.Paths = append(matrix.Paths, buildPathResult("IPv4 direct", "Direct connection restricted to IPv4", ipv4Run, false))

	ipv6Run, _ := Run(ctx, Options{
		Target:        opts.Target,
		BypassProxy:   true,
		IPv6Only:      true,
		ForcedNetwork: "tcp6",
		Method:        opts.Method,
		Timeout:       opts.Timeout,
		DialTimeout:   opts.DialTimeout,
	})
	matrix.Paths = append(matrix.Paths, buildPathResult("IPv6 direct", "Direct connection restricted to IPv6", ipv6Run, false))

	if opts.Resolver != "" {
		resRun, _ := Run(ctx, Options{
			Target:      opts.Target,
			BypassProxy: true,
			Resolver:    opts.Resolver,
			Method:      opts.Method,
			Timeout:     opts.Timeout,
			DialTimeout: opts.DialTimeout,
		})
		matrix.Paths = append(matrix.Paths, buildPathResult("Alternate resolver", fmt.Sprintf("Direct connection via custom DNS resolver %s", opts.Resolver), resRun, false))
	}

	diffs, primaryObs, findings := ExplainMatrix(matrix)
	matrix.ObservedDifferences = diffs
	matrix.MostRelevantObservation = primaryObs
	matrix.Findings = findings

	return matrix, nil
}

func buildPathResult(name, desc string, run *RunResult, isAppPath bool) PathResult {
	res := PathResult{
		Name:        name,
		Description: desc,
		Run:         run,
	}

	if run == nil {
		res.Status = StatusFail
		res.Error = "probe execution failed"
		return res
	}

	res.Status = run.OverallStatus
	res.BlockingLayer = run.FirstBlockingLayer

	if run.DNS != nil {
		res.Resolver = run.DNS.Resolver
	}

	if run.HTTP != nil {
		res.HTTPStatus = run.HTTP.StatusCode
		res.Duration = run.HTTP.Timings.Total
		res.RemoteAddr = run.HTTP.RemoteAddr
		res.UsedProxy = run.HTTP.UsedProxy
		if isAppPath && run.Environment.ProxyForTarget {
			res.TLSIssuer = run.HTTP.TLSIssuer
			res.TLSVersion = run.HTTP.TLSVersion
		}
	} else if run.TCP != nil {
		res.Duration = run.TCP.Duration
	} else if run.DNS != nil {
		res.Duration = run.DNS.Duration
	}

	if (!isAppPath || !run.Environment.ProxyForTarget) && run.TLS != nil && run.TLS.LeafIssuer != "" {
		res.TLSIssuer = run.TLS.LeafIssuer
		res.TLSVersion = run.TLS.Version
	}

	if run.TCP != nil {
		for _, a := range run.TCP.Attempts {
			if a.Status == StatusPass {
				res.ConnectedIP = a.IP
				break
			}
		}
	}

	if run.OverallStatus != StatusPass {
		if run.FirstBlockingLayer == LayerDNS && run.DNS != nil {
			res.Error = run.DNS.Error
		} else if run.FirstBlockingLayer == LayerTCP && run.TCP != nil {
			res.Error = run.TCP.ErrorSummary
			if run.TCP.Status == StatusTimeout {
				res.Status = StatusTimeout
			}
		} else if run.FirstBlockingLayer == LayerTLS && run.TLS != nil {
			res.Error = run.TLS.Error
		} else if run.FirstBlockingLayer == LayerHTTP && run.HTTP != nil {
			res.Error = run.HTTP.Error
		}
	}

	return res
}

// Snapshots and diffing

func FromRunResult(run *RunResult) *Snapshot {
	if run == nil {
		return nil
	}
	return &Snapshot{
		SchemaVersion:      CurrentSchemaVersion,
		ToolVersion:        CurrentToolVersion,
		CapturedAt:         time.Now().UTC(),
		Target:             run.Target,
		Environment:        run.Environment,
		DNS:                run.DNS,
		TCP:                run.TCP,
		TLS:                run.TLS,
		HTTP:               run.HTTP,
		OverallStatus:      run.OverallStatus,
		FirstBlockingLayer: run.FirstBlockingLayer,
	}
}

func WriteSnapshotJSON(w io.Writer, snap *Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

func LoadSnapshotFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open snapshot file %s: %w", path, err)
	}

	cleanData, err := decodeTextBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode snapshot file %s: %w", path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(cleanData, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot JSON in %s: %w", path, err)
	}

	if snap.SchemaVersion <= 0 {
		return nil, fmt.Errorf("invalid snapshot in %s: missing schema_version", path)
	}
	if snap.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("unsupported snapshot schema version %d in %s (current supported version is %d)", snap.SchemaVersion, path, CurrentSchemaVersion)
	}

	return &snap, nil
}

// decodeTextBytes strips UTF-8 BOM or converts UTF-16 LE/BE bytes to UTF-8.
func decodeTextBytes(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), nil
	}
	if bytes.HasPrefix(data, []byte("\xff\xfe")) {
		raw := data[2:]
		if len(raw)%2 != 0 {
			return nil, errors.New("invalid odd-length UTF-16 LE data")
		}
		u16 := make([]uint16, len(raw)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(raw[i*2]) | (uint16(raw[i*2+1]) << 8)
		}
		return []byte(string(utf16.Decode(u16))), nil
	}
	if bytes.HasPrefix(data, []byte("\xfe\xff")) {
		raw := data[2:]
		if len(raw)%2 != 0 {
			return nil, errors.New("invalid odd-length UTF-16 BE data")
		}
		u16 := make([]uint16, len(raw)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = (uint16(raw[i*2]) << 8) | uint16(raw[i*2+1])
		}
		return []byte(string(utf16.Decode(u16))), nil
	}
	return data, nil
}

func DiffSnapshots(s1, s2 *Snapshot) *SnapshotDiffResult {
	if s1 == nil || s2 == nil {
		return nil
	}

	result := &SnapshotDiffResult{
		Target1:    s1.Target.Original,
		Target2:    s2.Target.Original,
		Timestamp1: s1.CapturedAt,
		Timestamp2: s2.CapturedAt,
	}

	var diffs []SnapshotDiffItem

	if s1.Target.Original != s2.Target.Original {
		diffs = append(diffs, SnapshotDiffItem{
			Category: "Target",
			Message:  "Target endpoint changed",
			From:     s1.Target.Original,
			To:       s2.Target.Original,
		})
	}

	if s1.OverallStatus != s2.OverallStatus {
		diffs = append(diffs, SnapshotDiffItem{
			Category: "Status",
			Message:  "Overall diagnostic status changed",
			From:     string(s1.OverallStatus),
			To:       string(s2.OverallStatus),
		})
	}

	if s1.FirstBlockingLayer != s2.FirstBlockingLayer {
		fromLayer := string(s1.FirstBlockingLayer)
		if fromLayer == "" {
			fromLayer = "none"
		}
		toLayer := string(s2.FirstBlockingLayer)
		if toLayer == "" {
			toLayer = "none"
		}
		diffs = append(diffs, SnapshotDiffItem{
			Category: "Blocking Layer",
			Message:  "First blocking layer changed",
			From:     fromLayer,
			To:       toLayer,
		})
	}

	if s1.DNS != nil && s2.DNS != nil {
		if s1.DNS.Status != s2.DNS.Status {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "DNS Status",
				Message:  "DNS status changed",
				From:     string(s1.DNS.Status),
				To:       string(s2.DNS.Status),
			})
		}

		v4A := strings.Join(sortedUnique(s1.DNS.IPv4Addrs), ", ")
		v4B := strings.Join(sortedUnique(s2.DNS.IPv4Addrs), ", ")
		if v4A != v4B {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "DNS IPv4",
				Message:  "Resolved IPv4 addresses changed",
				From:     v4A,
				To:       v4B,
			})
		}

		v6A := strings.Join(sortedUnique(s1.DNS.IPv6Addrs), ", ")
		v6B := strings.Join(sortedUnique(s2.DNS.IPv6Addrs), ", ")
		if v6A != v6B {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "DNS IPv6",
				Message:  "Resolved IPv6 addresses changed",
				From:     v6A,
				To:       v6B,
			})
		}
	} else if (s1.DNS == nil) != (s2.DNS == nil) {
		diffs = append(diffs, SnapshotDiffItem{
			Category: "DNS",
			Message:  "DNS resolution presence changed",
		})
	}

	if s1.TCP != nil && s2.TCP != nil {
		if s1.TCP.Status != s2.TCP.Status {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TCP Status",
				Message:  "TCP connection status changed",
				From:     string(s1.TCP.Status),
				To:       string(s2.TCP.Status),
			})
		}
		if s1.TCP.IPv4Success != s2.TCP.IPv4Success {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TCP IPv4",
				Message:  "IPv4 TCP reachability changed",
				From:     fmt.Sprintf("success=%t", s1.TCP.IPv4Success),
				To:       fmt.Sprintf("success=%t", s2.TCP.IPv4Success),
			})
		}
		if s1.TCP.IPv6Success != s2.TCP.IPv6Success {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TCP IPv6",
				Message:  "IPv6 TCP reachability changed",
				From:     fmt.Sprintf("success=%t", s1.TCP.IPv6Success),
				To:       fmt.Sprintf("success=%t", s2.TCP.IPv6Success),
			})
		}
	}

	if s1.TLS != nil && s2.TLS != nil {
		if s1.TLS.Status != s2.TLS.Status {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TLS Status",
				Message:  "TLS validation status changed",
				From:     string(s1.TLS.Status),
				To:       string(s2.TLS.Status),
			})
		}
		if s1.TLS.LeafIssuer != s2.TLS.LeafIssuer {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TLS Issuer",
				Message:  "TLS Certificate Issuer changed",
				From:     s1.TLS.LeafIssuer,
				To:       s2.TLS.LeafIssuer,
			})
		}
		if s1.TLS.HostnameValid != s2.TLS.HostnameValid {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "TLS Hostname",
				Message:  "TLS Hostname validation changed",
				From:     fmt.Sprintf("valid=%t", s1.TLS.HostnameValid),
				To:       fmt.Sprintf("valid=%t", s2.TLS.HostnameValid),
			})
		}
	}

	if s1.HTTP != nil && s2.HTTP != nil {
		if s1.HTTP.StatusCode != s2.HTTP.StatusCode {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "HTTP Status",
				Message:  "HTTP status code changed",
				From:     fmt.Sprintf("%d (%s)", s1.HTTP.StatusCode, s1.HTTP.StatusText),
				To:       fmt.Sprintf("%d (%s)", s2.HTTP.StatusCode, s2.HTTP.StatusText),
			})
		}
		if s1.HTTP.Status != s2.HTTP.Status {
			diffs = append(diffs, SnapshotDiffItem{
				Category: "HTTP Transport",
				Message:  "HTTP transport status changed",
				From:     string(s1.HTTP.Status),
				To:       string(s2.HTTP.Status),
			})
		}
	}

	if s1.Environment.SelectedProxy != s2.Environment.SelectedProxy {
		diffs = append(diffs, SnapshotDiffItem{
			Category: "Proxy",
			Message:  "Selected HTTP proxy changed",
			From:     s1.Environment.SelectedProxy,
			To:       s2.Environment.SelectedProxy,
		})
	}

	result.Differences = diffs
	if len(diffs) == 0 {
		result.Summary = "No semantic differences observed between snapshots."
	} else {
		result.Summary = fmt.Sprintf("Observed %d semantic difference(s) between snapshots.", len(diffs))
	}

	return result
}

func sortedUnique(slice []string) []string {
	if len(slice) == 0 {
		return nil
	}
	m := make(map[string]bool)
	for _, s := range slice {
		if s != "" {
			m[s] = true
		}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Formatting & output

func PrintJSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func PrintTerminalRun(w io.Writer, res *RunResult) {
	if res == nil {
		return
	}

	fmt.Fprintf(w, "\nTarget: %s\n\n", SanitizeTerminalOneLine(res.Target.Original))

	tw := tabwriter.NewWriter(w, 0, 8, 3, ' ', 0)
	fmt.Fprintf(tw, "LAYER\tRESULT\tDURATION\tDETAILS\n")

	if res.DNS != nil {
		dnsDetails := ""
		if res.DNS.Status == StatusSkipped {
			dnsDetails = "Direct IP target"
		} else if res.DNS.Status == StatusPass {
			var parts []string
			if len(res.DNS.IPv4Addrs) > 0 {
				parts = append(parts, fmt.Sprintf("%d IPv4 (%s)", len(res.DNS.IPv4Addrs), strings.Join(res.DNS.IPv4Addrs, ", ")))
			}
			if len(res.DNS.IPv6Addrs) > 0 {
				parts = append(parts, fmt.Sprintf("%d IPv6 (%s)", len(res.DNS.IPv6Addrs), strings.Join(res.DNS.IPv6Addrs, ", ")))
			}
			if len(res.DNS.CNAMEs) > 0 {
				parts = append(parts, fmt.Sprintf("CNAME -> %s", res.DNS.CNAMEs[0]))
			}
			dnsDetails = strings.Join(parts, "; ")
		} else {
			dnsDetails = res.DNS.Error
		}
		fmt.Fprintf(tw, "DNS\t%s\t%s\t%s\n", res.DNS.Status, res.DNS.Duration.String(), SanitizeTerminalOneLine(dnsDetails))
	}

	if res.TCP != nil {
		for _, a := range res.TCP.Attempts {
			layerName := "IPv4 TCP"
			if a.Family == "ipv6" {
				layerName = "IPv6 TCP"
			}
			details := fmt.Sprintf("%s:%d", a.IP, a.Port)
			if a.Error != "" {
				details = fmt.Sprintf("%s (%s)", details, a.Error)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", layerName, a.Status, a.Duration.String(), SanitizeTerminalOneLine(details))
		}
	}

	if res.TLS != nil && res.Target.UseTLS {
		details := ""
		if res.TLS.Connected {
			var parts []string
			if res.TLS.Version != "" {
				parts = append(parts, res.TLS.Version)
			}
			if res.TLS.LeafIssuer != "" {
				parts = append(parts, fmt.Sprintf("Issuer: %s", res.TLS.LeafIssuer))
			}
			if res.TLS.ALPN != "" {
				parts = append(parts, fmt.Sprintf("ALPN: %s", res.TLS.ALPN))
			}
			if !res.TLS.HostnameValid {
				parts = append(parts, "Hostname Mismatch")
			}
			if !res.TLS.ChainValid {
				parts = append(parts, "Untrusted Chain")
			}
			if !res.TLS.ExpiryValid {
				parts = append(parts, "Expired/Not Valid")
			}
			details = strings.Join(parts, "; ")
		} else {
			details = res.TLS.Error
		}
		fmt.Fprintf(tw, "TLS\t%s\t%s\t%s\n", res.TLS.Status, res.TLS.HandshakeDuration.String(), SanitizeTerminalOneLine(details))
	}

	if res.HTTP != nil && res.Target.UseHTTP {
		httpStatusStr := string(res.HTTP.Status)
		if res.HTTP.StatusCode > 0 {
			httpStatusStr = fmt.Sprintf("%d", res.HTTP.StatusCode)
		}
		details := ""
		if res.HTTP.StatusCode > 0 {
			details = fmt.Sprintf("TTFB: %s, %s", res.HTTP.Timings.TTFB.String(), res.HTTP.Proto)
			if len(res.HTTP.Redirects) > 0 {
				details += fmt.Sprintf(" (%d redirects)", len(res.HTTP.Redirects))
			}
		} else {
			details = res.HTTP.Error
		}
		fmt.Fprintf(tw, "HTTP\t%s\t%s\t%s\n", httpStatusStr, res.HTTP.Timings.Total.String(), SanitizeTerminalOneLine(details))
	}

	_ = tw.Flush()

	if res.Environment.HasProxyConfig {
		fmt.Fprintf(w, "\nEnvironment:\n")
		if res.Environment.SelectedProxy != "" {
			fmt.Fprintf(w, "  Selected Proxy: %s\n", SanitizeTerminalOneLine(res.Environment.SelectedProxy))
		}
		if res.Environment.HTTPSProxy != "" {
			fmt.Fprintf(w, "  HTTPS_PROXY:    %s\n", SanitizeTerminalOneLine(res.Environment.HTTPSProxy))
		}
		if res.Environment.HTTPProxy != "" {
			fmt.Fprintf(w, "  HTTP_PROXY:     %s\n", SanitizeTerminalOneLine(res.Environment.HTTPProxy))
		}
		if res.Environment.NoProxy != "" {
			fmt.Fprintf(w, "  NO_PROXY:       %s\n", SanitizeTerminalOneLine(res.Environment.NoProxy))
		}
	}

	if res.AnalysisSummary != "" {
		fmt.Fprintf(w, "\nResult: %s\n", SanitizeTerminalOneLine(res.AnalysisSummary))
	}

	if len(res.Findings) > 0 {
		fmt.Fprintf(w, "\nFindings:\n")
		for _, f := range res.Findings {
			badge := "INFO"
			if f.Severity == SeverityCritical {
				badge = "FAIL"
			} else if f.Severity == SeverityWarning {
				badge = "WARN"
			}

			fmt.Fprintf(w, "  [%s] %s\n", badge, SanitizeTerminalOneLine(f.Title))
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "    Observed:\n")
				for _, e := range f.Evidence {
					fmt.Fprintf(w, "      - %s\n", SanitizeTerminalOneLine(e))
				}
			}
			if len(f.PossibleCauses) > 0 {
				fmt.Fprintf(w, "    Possible causes:\n")
				for _, c := range f.PossibleCauses {
					fmt.Fprintf(w, "      - %s\n", SanitizeTerminalOneLine(c))
				}
			}
		}
	}

	if res.Verbose && len(res.TraceEvents) > 0 {
		fmt.Fprintf(w, "\nTrace Logs (--verbose):\n")
		for _, ev := range res.TraceEvents {
			fmt.Fprintf(w, "  +%-8s [%-6s] %s\n", ev.Elapsed.String(), ev.Layer, SanitizeTerminalOneLine(ev.Message))
			if ev.Details != "" {
				fmt.Fprintf(w, "              %s\n", SanitizeTerminalOneLine(ev.Details))
			}
		}
	}

	fmt.Fprintln(w)
}

func PrintTerminalMatrix(w io.Writer, matrix *MatrixResult) {
	if matrix == nil {
		return
	}

	fmt.Fprintf(w, "\nTarget: %s\n\n", SanitizeTerminalOneLine(matrix.Target.Original))

	tw := tabwriter.NewWriter(w, 0, 8, 3, ' ', 0)
	fmt.Fprintf(tw, "PATH\tRESULT\tHTTP\tTLS ISSUER\tDURATION\n")

	for _, p := range matrix.Paths {
		httpCol := "-"
		if p.HTTPStatus > 0 {
			httpCol = fmt.Sprintf("%d", p.HTTPStatus)
		}
		issuerCol := "-"
		if p.TLSIssuer != "" {
			issuerCol = p.TLSIssuer
		}
		durCol := "-"
		if p.Duration > 0 {
			durCol = p.Duration.String()
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			SanitizeTerminalOneLine(p.Name),
			p.Status,
			httpCol,
			SanitizeTerminalOneLine(issuerCol),
			durCol,
		)
	}
	_ = tw.Flush()

	if matrix.Environment.HasProxyConfig {
		fmt.Fprintf(w, "\nEnvironment:\n")
		if matrix.Environment.SelectedProxy != "" {
			fmt.Fprintf(w, "  Selected Proxy: %s\n", SanitizeTerminalOneLine(matrix.Environment.SelectedProxy))
		}
		if matrix.Environment.HTTPSProxy != "" {
			fmt.Fprintf(w, "  HTTPS_PROXY:    %s\n", SanitizeTerminalOneLine(matrix.Environment.HTTPSProxy))
		}
		if matrix.Environment.HTTPProxy != "" {
			fmt.Fprintf(w, "  HTTP_PROXY:     %s\n", SanitizeTerminalOneLine(matrix.Environment.HTTPProxy))
		}
		if matrix.Environment.NoProxy != "" {
			fmt.Fprintf(w, "  NO_PROXY:       %s\n", SanitizeTerminalOneLine(matrix.Environment.NoProxy))
		}
	}

	if len(matrix.ObservedDifferences) > 0 {
		fmt.Fprintf(w, "\nObserved Differences:\n")
		for i, diff := range matrix.ObservedDifferences {
			fmt.Fprintf(w, "  %d. %s\n", i+1, SanitizeTerminalOneLine(diff))
		}
	}

	if matrix.MostRelevantObservation != "" {
		fmt.Fprintf(w, "\nPrimary Observation:\n  %s\n", SanitizeTerminalOneLine(matrix.MostRelevantObservation))
	}

	if len(matrix.Findings) > 0 {
		fmt.Fprintf(w, "\nFindings:\n")
		for _, f := range matrix.Findings {
			badge := "INFO"
			if f.Severity == SeverityCritical {
				badge = "FAIL"
			} else if f.Severity == SeverityWarning {
				badge = "WARN"
			}
			fmt.Fprintf(w, "  [%s] %s\n", badge, SanitizeTerminalOneLine(f.Title))
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "    Observed:\n")
				for _, e := range f.Evidence {
					fmt.Fprintf(w, "      - %s\n", SanitizeTerminalOneLine(e))
				}
			}
			if len(f.PossibleCauses) > 0 {
				fmt.Fprintf(w, "    Possible causes:\n")
				for _, c := range f.PossibleCauses {
					fmt.Fprintf(w, "      - %s\n", SanitizeTerminalOneLine(c))
				}
			}
		}
	}

	fmt.Fprintln(w)
}

func PrintTerminalDiff(w io.Writer, diff *SnapshotDiffResult) {
	if diff == nil {
		return
	}

	fmt.Fprintf(w, "\nSnapshot Diff:\n")
	fmt.Fprintf(w, "  Target 1: %s (%s)\n", SanitizeTerminalOneLine(diff.Target1), diff.Timestamp1.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "  Target 2: %s (%s)\n", SanitizeTerminalOneLine(diff.Target2), diff.Timestamp2.Format("2006-01-02 15:04:05 UTC"))

	fmt.Fprintf(w, "\nSummary:\n  %s\n", SanitizeTerminalOneLine(diff.Summary))

	if len(diff.Differences) > 0 {
		fmt.Fprintf(w, "\nDifferences:\n")
		for _, d := range diff.Differences {
			if d.From != "" || d.To != "" {
				fmt.Fprintf(w, "  [%s] %s\n        From: %s\n        To:   %s\n",
					SanitizeTerminalOneLine(d.Category),
					SanitizeTerminalOneLine(d.Message),
					SanitizeTerminalOneLine(d.From),
					SanitizeTerminalOneLine(d.To),
				)
			} else {
				fmt.Fprintf(w, "  [%s] %s\n",
					SanitizeTerminalOneLine(d.Category),
					SanitizeTerminalOneLine(d.Message),
				)
			}
		}
	}
	fmt.Fprintln(w)
}

// CLI dispatcher

func main() {
	code := runMain()
	os.Exit(code)
}

func runMain() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) < 2 {
		printUsage()
		return ExitInputError
	}

	firstArg := os.Args[1]

	if firstArg == "--version" || firstArg == "version" {
		fmt.Printf("netwhy %s\n", Version)
		return ExitOK
	}

	if firstArg == "-h" || firstArg == "--help" || firstArg == "help" {
		printUsage()
		return ExitOK
	}

	switch firstArg {
	case "matrix":
		return runMatrixCmd(ctx, os.Args[2:])
	case "snapshot":
		return runSnapshotCmd(ctx, os.Args[2:])
	case "diff":
		return runDiffCmd(ctx, os.Args[2:])
	default:
		return runSingleCmd(ctx, os.Args[1:])
	}
}

func runSingleCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("netwhy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOutput := fs.Bool("json", false, "Output machine-readable JSON")
	verbose := fs.Bool("verbose", false, "Enable verbose execution trace logs")
	fs.BoolVar(verbose, "v", false, "Enable verbose execution trace logs (shorthand)")
	ipv4Only := fs.Bool("ipv4", false, "Restrict connections to IPv4")
	ipv6Only := fs.Bool("ipv6", false, "Restrict connections to IPv6")
	resolver := fs.String("resolver", "", "Use custom DNS resolver IP via wire client")
	method := fs.String("method", "HEAD", "HTTP request method (HEAD, GET, etc.)")
	timeout := fs.Duration("timeout", 10*time.Second, "Overall timeout duration")
	dialTimeout := fs.Duration("dial-timeout", 3*time.Second, "Individual TCP/TLS dial timeout")

	if err := fs.Parse(args); err != nil {
		return ExitInputError
	}

	if *ipv4Only && *ipv6Only {
		fmt.Fprintf(os.Stderr, "Error: cannot specify both --ipv4 and --ipv6\n")
		return ExitInputError
	}
	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: --timeout must be positive\n")
		return ExitInputError
	}
	if *dialTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: --dial-timeout must be positive\n")
		return ExitInputError
	}

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintf(os.Stderr, "Error: target endpoint required\n\n")
		printUsage()
		return ExitInputError
	}
	if len(rest) > 1 {
		fmt.Fprintf(os.Stderr, "Error: unexpected extra argument %q\n\n", rest[1])
		return ExitInputError
	}
	targetArg := rest[0]

	opts := Options{
		Target:      targetArg,
		IPv4Only:    *ipv4Only,
		IPv6Only:    *ipv6Only,
		Resolver:    *resolver,
		Method:      *method,
		Timeout:     *timeout,
		DialTimeout: *dialTimeout,
		Verbose:     *verbose,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitInputError
	}

	if *jsonOutput {
		if err := PrintJSON(os.Stdout, res); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			return ExitInternalError
		}
	} else {
		PrintTerminalRun(os.Stdout, res)
	}

	return exitCodeForRun(res)
}

func runMatrixCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("netwhy matrix", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOutput := fs.Bool("json", false, "Output machine-readable JSON")
	verbose := fs.Bool("verbose", false, "Enable verbose output")
	fs.BoolVar(verbose, "v", false, "Enable verbose output (shorthand)")
	resolver := fs.String("resolver", "", "Include alternate DNS resolver in matrix comparison")
	method := fs.String("method", "HEAD", "HTTP request method")
	timeout := fs.Duration("timeout", 10*time.Second, "Overall timeout duration per path")
	dialTimeout := fs.Duration("dial-timeout", 3*time.Second, "Individual TCP/TLS dial timeout")

	if err := fs.Parse(args); err != nil {
		return ExitInputError
	}

	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: --timeout must be positive\n")
		return ExitInputError
	}
	if *dialTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: --dial-timeout must be positive\n")
		return ExitInputError
	}

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintf(os.Stderr, "Error: target endpoint required for matrix\n\nUsage: netwhy matrix [options] <target>\n")
		return ExitInputError
	}
	if len(rest) > 1 {
		fmt.Fprintf(os.Stderr, "Error: unexpected extra argument %q\n", rest[1])
		return ExitInputError
	}
	targetArg := rest[0]

	matrixOpts := MatrixOptions{
		Target:      targetArg,
		Resolver:    *resolver,
		Method:      *method,
		Timeout:     *timeout,
		DialTimeout: *dialTimeout,
	}

	matrixRes, err := RunMatrix(ctx, matrixOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitInputError
	}
	matrixRes.Verbose = *verbose

	if *jsonOutput {
		if err := PrintJSON(os.Stdout, matrixRes); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			return ExitInternalError
		}
	} else {
		PrintTerminalMatrix(os.Stdout, matrixRes)
	}

	for _, p := range matrixRes.Paths {
		if p.Status == StatusPass {
			return ExitOK
		}
	}
	return ExitTCPBlocking
}

func runSnapshotCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("netwhy snapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	ipv4Only := fs.Bool("ipv4", false, "Restrict connections to IPv4")
	ipv6Only := fs.Bool("ipv6", false, "Restrict connections to IPv6")
	resolver := fs.String("resolver", "", "Use custom DNS resolver IP")
	method := fs.String("method", "HEAD", "HTTP request method")
	timeout := fs.Duration("timeout", 10*time.Second, "Overall timeout duration")
	dialTimeout := fs.Duration("dial-timeout", 3*time.Second, "Dial timeout")
	verbose := fs.Bool("verbose", false, "Include verbose trace logs in snapshot")
	fs.BoolVar(verbose, "v", false, "Include verbose trace logs (shorthand)")

	if err := fs.Parse(args); err != nil {
		return ExitInputError
	}

	if *ipv4Only && *ipv6Only {
		fmt.Fprintf(os.Stderr, "Error: cannot specify both --ipv4 and --ipv6\n")
		return ExitInputError
	}

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintf(os.Stderr, "Error: target endpoint required for snapshot\n\nUsage: netwhy snapshot [options] <target>\n")
		return ExitInputError
	}
	if len(rest) > 1 {
		fmt.Fprintf(os.Stderr, "Error: unexpected extra argument %q\n", rest[1])
		return ExitInputError
	}
	targetArg := rest[0]

	opts := Options{
		Target:      targetArg,
		IPv4Only:    *ipv4Only,
		IPv6Only:    *ipv6Only,
		Resolver:    *resolver,
		Method:      *method,
		Timeout:     *timeout,
		DialTimeout: *dialTimeout,
		Verbose:     *verbose,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitInputError
	}

	snap := FromRunResult(res)
	if err := WriteSnapshotJSON(os.Stdout, snap); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving snapshot: %v\n", err)
		return ExitInternalError
	}

	return exitCodeForRun(res)
}

func runDiffCmd(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("netwhy diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOutput := fs.Bool("json", false, "Output machine-readable JSON diff")

	if err := fs.Parse(args); err != nil {
		return ExitInputError
	}

	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintf(os.Stderr, "Error: two snapshot JSON files required for diff (e.g. netwhy diff before.json after.json)\n\nUsage: netwhy diff [options] <file1.json> <file2.json>\n")
		return ExitInputError
	}
	if len(rest) > 2 {
		fmt.Fprintf(os.Stderr, "Error: unexpected extra argument %q\n", rest[2])
		return ExitInputError
	}

	snap1, err := LoadSnapshotFile(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading first snapshot: %v\n", err)
		return ExitInputError
	}

	snap2, err := LoadSnapshotFile(rest[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading second snapshot: %v\n", err)
		return ExitInputError
	}

	diffRes := DiffSnapshots(snap1, snap2)

	if *jsonOutput {
		if err := PrintJSON(os.Stdout, diffRes); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			return ExitInternalError
		}
	} else {
		PrintTerminalDiff(os.Stdout, diffRes)
	}

	return ExitOK
}

func exitCodeForRun(res *RunResult) int {
	if res == nil {
		return ExitInternalError
	}
	if res.OverallStatus == StatusPass || res.OverallStatus == StatusPartial {
		return ExitOK
	}

	switch res.FirstBlockingLayer {
	case LayerDNS:
		return ExitDNSBlocking
	case LayerTCP:
		return ExitTCPBlocking
	case LayerTLS:
		return ExitTLSBlocking
	case LayerHTTP:
		return ExitHTTPTransport
	default:
		return ExitTCPBlocking
	}
}

func printUsage() {
	usage := `netwhy - Differential Network Path Debugger

USAGE:
  netwhy [options] <target>
  netwhy matrix [options] <target>
  netwhy snapshot [options] <target>
  netwhy diff [options] <file1.json> <file2.json>

COMMANDS:
  <target>          Run single diagnostic probe (DNS -> TCP -> TLS -> HTTP)
  matrix <target>   Compare pathways (Application, Direct, IPv4, IPv6, Alternate Resolver)
  snapshot <target> Capture diagnostic facts into a structured JSON snapshot
  diff <f1> <f2>    Compare two snapshot JSON files

TARGET FORMATS:
  https://api.example.com
  http://example.com:8080
  example.com:443
  127.0.0.1:8080
  [2001:db8::1]:443
  example.com

OPTIONS:
  -v, --verbose     Enable trace logging
  --json            Output JSON format
  --ipv4            Restrict to IPv4
  --ipv6            Restrict to IPv6
  --resolver <ip>   Use custom DNS resolver IP via wire client
  --method <name>   HTTP request method (default: HEAD)
  --timeout <dur>   Overall diagnostic timeout (default: 10s)
  --dial-timeout <d> Individual dial timeout (default: 3s)
  --version         Print version
  -h, --help        Print help

EXIT CODES:
  0  Endpoint reached or HTTP response received
  1  CLI or target syntax error
  2  DNS blocking failure
  3  TCP blocking failure
  4  TLS blocking failure
  5  HTTP transport failure
  6  Internal error
`
	fmt.Print(usage)
}
