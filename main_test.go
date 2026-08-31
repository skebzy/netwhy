package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		res      *RunResult
		wantCode int
	}{
		{
			name: "successful run",
			res: &RunResult{
				OverallStatus: StatusPass,
			},
			wantCode: ExitOK,
		},
		{
			name: "partial ipv6 degradation is still overall exit 0",
			res: &RunResult{
				OverallStatus: StatusPartial,
			},
			wantCode: ExitOK,
		},
		{
			name: "dns blocking failure",
			res: &RunResult{
				OverallStatus:      StatusFail,
				FirstBlockingLayer: LayerDNS,
			},
			wantCode: ExitDNSBlocking,
		},
		{
			name: "tcp blocking failure",
			res: &RunResult{
				OverallStatus:      StatusFail,
				FirstBlockingLayer: LayerTCP,
			},
			wantCode: ExitTCPBlocking,
		},
		{
			name: "tls blocking failure",
			res: &RunResult{
				OverallStatus:      StatusFail,
				FirstBlockingLayer: LayerTLS,
			},
			wantCode: ExitTLSBlocking,
		},
		{
			name: "http transport failure",
			res: &RunResult{
				OverallStatus:      StatusFail,
				FirstBlockingLayer: LayerHTTP,
			},
			wantCode: ExitHTTPTransport,
		},
		{
			name:     "nil result returns internal error",
			res:      nil,
			wantCode: ExitInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeForRun(tt.res)
			if got != tt.wantCode {
				t.Errorf("exitCodeForRun() = %d, want %d", got, tt.wantCode)
			}
		})
	}
}

func TestLocalIntegrationServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := Options{
		Target:      ts.URL,
		BypassProxy: true,
		Method:      "HEAD",
	}

	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.OverallStatus != StatusPass {
		t.Errorf("OverallStatus = %s, want PASS", res.OverallStatus)
	}
	if res.HTTP == nil || res.HTTP.StatusCode != 200 {
		t.Errorf("HTTP status mismatch: %+v", res.HTTP)
	}

	code := exitCodeForRun(res)
	if code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
}

func TestPathPinning_AlternateDNSIPUsedByHTTP(t *testing.T) {
	var receivedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	serverIP, serverPort, _ := net.SplitHostPort(serverURL.Host)

	ctx := context.Background()
	opts := HTTPOptions{
		Method:        "GET",
		TargetURL:     fmt.Sprintf("http://custom-virtual-host.test:%s/health", serverPort),
		TargetHost:    "custom-virtual-host.test",
		CustomDNSIP:   serverIP,
		Timeout:       2 * time.Second,
		DialTimeout:   1 * time.Second,
		UseProxy:      false,
		NetworkFamily: "tcp",
	}

	res := ProbeHTTP(ctx, opts)
	if res.Status != StatusPass {
		t.Fatalf("HTTP probe failed with custom IP pinning: %s", res.Error)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
	if receivedHost != fmt.Sprintf("custom-virtual-host.test:%s", serverPort) {
		t.Errorf("Server received Host %q, want 'custom-virtual-host.test:%s'", receivedHost, serverPort)
	}
}

func TestPathPinning_RedirectDoesNotCorruptNewHost(t *testing.T) {
	var targetServerHits int
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetServerHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL+"/destination", http.StatusFound)
	}))
	defer redirectServer.Close()

	redirURL, _ := url.Parse(redirectServer.URL)
	redirIP, redirPort, _ := net.SplitHostPort(redirURL.Host)

	ctx := context.Background()
	opts := HTTPOptions{
		Method:        "GET",
		TargetURL:     fmt.Sprintf("http://initial-host.test:%s/start", redirPort),
		TargetHost:    "initial-host.test",
		CustomDNSIP:   redirIP,
		Timeout:       3 * time.Second,
		DialTimeout:   1 * time.Second,
		UseProxy:      false,
		NetworkFamily: "tcp",
	}

	res := ProbeHTTP(ctx, opts)
	if res.Status != StatusPass {
		t.Fatalf("HTTP probe failed on redirect: %s", res.Error)
	}
	if len(res.Redirects) != 1 {
		t.Errorf("Expected 1 redirect, got %d (%v)", len(res.Redirects), res.Redirects)
	}
	if targetServerHits != 1 {
		t.Errorf("Target server received %d hits, want 1", targetServerHits)
	}
}

type testCertBundle struct {
	cert     tls.Certificate
	caPool   *x509.CertPool
	leafCert *x509.Certificate
}

func createTestPKI(t *testing.T, leafNames []string, leafIPs []net.IP, notBefore, notAfter time.Time) testCertBundle {
	t.Helper()

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization: []string{"Netwhy Test Authority"},
			CommonName:   "Netwhy Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Netwhy Test Service"},
			CommonName:   "Netwhy Leaf",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              leafNames,
		IPAddresses:           leafIPs,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	parsedLeaf, _ := x509.ParseCertificate(leafDER)

	return testCertBundle{
		cert: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafPriv,
		},
		caPool:   caPool,
		leafCert: parsedLeaf,
	}
}

func TestProbeTLS_ValidTrustedChainAndHostname(t *testing.T) {
	now := time.Now()
	pki := createTestPKI(t, []string{"my-service.local"}, []net.IP{net.ParseIP("127.0.0.1")}, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pki.cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to listen TLS: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	ctx := context.Background()
	res := ProbeTLS(ctx, TLSOptions{
		ConnectHost: "127.0.0.1",
		ServerName:  "my-service.local",
		Port:        port,
		DialTimeout: 2 * time.Second,
		RootCAs:     pki.caPool,
	})

	if !res.Connected {
		t.Fatalf("TLS probe failed to connect: %s", res.Error)
	}
	if !res.HostnameValid {
		t.Errorf("HostnameValid = false, want true")
	}
	if !res.ExpiryValid {
		t.Errorf("ExpiryValid = false, want true")
	}
	if !res.ChainValid {
		t.Errorf("ChainValid = false, want true with supplied root pool")
	}
	if res.Status != StatusPass {
		t.Errorf("Status = %s, want PASS", res.Status)
	}
}

func TestProbeTLS_HostnameMismatch(t *testing.T) {
	now := time.Now()
	pki := createTestPKI(t, []string{"other-service.local"}, nil, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pki.cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to listen TLS: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	ctx := context.Background()
	res := ProbeTLS(ctx, TLSOptions{
		ConnectHost: "127.0.0.1",
		ServerName:  "expected-service.local",
		Port:        port,
		DialTimeout: 2 * time.Second,
		RootCAs:     pki.caPool,
	})

	if !res.Connected {
		t.Fatalf("TLS probe failed to connect: %s", res.Error)
	}
	if res.HostnameValid {
		t.Errorf("HostnameValid = true, want false for mismatched hostname")
	}
	if res.Status != StatusFail {
		t.Errorf("Status = %s, want FAIL", res.Status)
	}
}

func TestProbeTLS_ExpiredCertificate(t *testing.T) {
	past := time.Now().Add(-10 * time.Hour)
	pki := createTestPKI(t, []string{"my-service.local"}, nil, past.Add(-5*time.Hour), past)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pki.cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to listen TLS: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	ctx := context.Background()
	res := ProbeTLS(ctx, TLSOptions{
		ConnectHost: "127.0.0.1",
		ServerName:  "my-service.local",
		Port:        port,
		DialTimeout: 2 * time.Second,
		RootCAs:     pki.caPool,
	})

	if !res.Connected {
		t.Fatalf("TLS probe failed to connect: %s", res.Error)
	}
	if res.ExpiryValid {
		t.Errorf("ExpiryValid = true, want false for expired cert")
	}
	if res.Status != StatusFail {
		t.Errorf("Status = %s, want FAIL", res.Status)
	}
}

func TestProbeTLS_ContextCancellationOnStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Server accepts TCP connection but never replies to TLS ClientHello.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var buf [256]byte
		_, _ = conn.Read(buf[:])
		time.Sleep(500 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := ProbeTLS(ctx, TLSOptions{
		ConnectHost: "127.0.0.1",
		ServerName:  "stall-test.local",
		Port:        port,
		DialTimeout: 2 * time.Second,
	})
	dur := time.Since(start)

	if dur > 400*time.Millisecond {
		t.Errorf("ProbeTLS did not respect context timeout, took %v", dur)
	}
	if res.Connected {
		t.Errorf("Connected = true on stalled handshake, want false")
	}
	if res.Status != StatusFail {
		t.Errorf("Status = %s, want FAIL", res.Status)
	}
}

func TestWireDNS_LocalUDPServer(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		req, err := ParseDNSMessage(buf[:n])
		if err != nil {
			return
		}

		respHeader := make([]byte, 12)
		binary.BigEndian.PutUint16(respHeader[0:2], req.Header.ID)
		binary.BigEndian.PutUint16(respHeader[2:4], 0x8180) // Response, NoError
		binary.BigEndian.PutUint16(respHeader[4:6], 1)      // QDCount = 1
		binary.BigEndian.PutUint16(respHeader[6:8], 1)      // ANCount = 1

		qname, _ := EncodeDomainName("test.local")
		var qtail [4]byte
		binary.BigEndian.PutUint16(qtail[0:2], TypeA)
		binary.BigEndian.PutUint16(qtail[2:4], ClassINET)

		ans := []byte{
			0xC0, 0x0C,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x3C,
			0x00, 0x04,
			198, 51, 100, 42,
		}

		var resp []byte
		resp = append(resp, respHeader...)
		resp = append(resp, qname...)
		resp = append(resp, qtail[:]...)
		resp = append(resp, ans...)

		_, _ = conn.WriteTo(resp, clientAddr)
	}()

	ctx := context.Background()
	msg, _, err := WireQuery(ctx, conn.LocalAddr().String(), "test.local", TypeA)
	if err != nil {
		t.Fatalf("WireQuery failed: %v", err)
	}

	if len(msg.Answers) != 1 || msg.Answers[0].Text != "198.51.100.42" {
		t.Errorf("Unexpected DNS answers: %+v", msg.Answers)
	}
}

func TestWireDNS_TCPFallbackOnTruncation(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}
	defer tcpLn.Close()
	_, tcpPortStr, _ := net.SplitHostPort(tcpLn.Addr().String())
	tcpPort, _ := strconv.Atoi(tcpPortStr)

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to resolve udp: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer udpConn.Close()

	go func() {
		buf := make([]byte, 512)
		n, clientAddr, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := ParseDNSMessage(buf[:n])
		if err != nil {
			return
		}

		respHeader := make([]byte, 12)
		binary.BigEndian.PutUint16(respHeader[0:2], req.Header.ID)
		binary.BigEndian.PutUint16(respHeader[2:4], 0x8380) // TC bit set (0x0200)

		qname, _ := EncodeDomainName("truncated.local")
		var qtail [4]byte
		binary.BigEndian.PutUint16(qtail[0:2], TypeA)
		binary.BigEndian.PutUint16(qtail[2:4], ClassINET)

		var resp []byte
		resp = append(resp, respHeader...)
		resp = append(resp, qname...)
		resp = append(resp, qtail[:]...)

		_, _ = udpConn.WriteTo(resp, clientAddr)
	}()

	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var lenBuf [2]byte
		_, _ = conn.Read(lenBuf[:])
		reqLen := binary.BigEndian.Uint16(lenBuf[:])
		reqBuf := make([]byte, reqLen)
		_, _ = conn.Read(reqBuf)

		req, _ := ParseDNSMessage(reqBuf)

		respHeader := make([]byte, 12)
		binary.BigEndian.PutUint16(respHeader[0:2], req.Header.ID)
		binary.BigEndian.PutUint16(respHeader[2:4], 0x8180)
		binary.BigEndian.PutUint16(respHeader[4:6], 1)
		binary.BigEndian.PutUint16(respHeader[6:8], 1)

		qname, _ := EncodeDomainName("truncated.local")
		var qtail [4]byte
		binary.BigEndian.PutUint16(qtail[0:2], TypeA)
		binary.BigEndian.PutUint16(qtail[2:4], ClassINET)

		ans := []byte{
			0xC0, 0x0C,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x3C,
			0x00, 0x04,
			203, 0, 113, 99,
		}

		var fullResp []byte
		fullResp = append(fullResp, respHeader...)
		fullResp = append(fullResp, qname...)
		fullResp = append(fullResp, qtail[:]...)
		fullResp = append(fullResp, ans...)

		var tcpSend [2]byte
		binary.BigEndian.PutUint16(tcpSend[:], uint16(len(fullResp)))
		_, _ = conn.Write(tcpSend[:])
		_, _ = conn.Write(fullResp)
	}()

	ctx := context.Background()
	msg, _, err := WireQuery(ctx, udpConn.LocalAddr().String(), "truncated.local", TypeA)
	if err != nil {
		t.Fatalf("WireQuery failed: %v", err)
	}

	if len(msg.Answers) != 1 || msg.Answers[0].Text != "203.0.113.99" {
		t.Errorf("TCP fallback answer mismatch: %+v", msg.Answers)
	}
}

func TestDNS_EncodingLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	enc, err := EncodeDomainName(label63 + ".com")
	if err != nil {
		t.Fatalf("63-byte label rejected: %v", err)
	}
	if len(enc) != 63+1+3+1+1 {
		t.Errorf("Unexpected length: %d", len(enc))
	}

	label64 := strings.Repeat("a", 64)
	_, err = EncodeDomainName(label64 + ".com")
	if err == nil {
		t.Fatal("expected error for 64-byte label, got nil")
	}

	longName := strings.Repeat("a.", 130)
	_, err = EncodeDomainName(longName)
	if err == nil {
		t.Fatal("expected error for >255 byte name, got nil")
	}
}

func TestDNS_DecodingDefenses(t *testing.T) {
	loopPacket := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
	}
	_, err := ParseDNSMessage(loopPacket)
	if err == nil {
		t.Fatal("expected loop error, got nil")
	}

	outOfRange := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x80,
		0x00, 0x01, 0x00, 0x01,
	}
	_, err = ParseDNSMessage(outOfRange)
	if err == nil {
		t.Fatal("expected error for out of range pointer, got nil")
	}
}

func TestSnapshot_JSONDurationUnits(t *testing.T) {
	snap := &Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		ToolVersion:   Version,
		CapturedAt:    time.Now().UTC(),
		Target:        TargetInfo{Original: "https://example.com"},
		DNS: &DNSResult{
			Status:    StatusPass,
			Duration:  DurationMs(123400 * time.Microsecond),
			IPv4Addrs: []string{"93.184.216.34"},
		},
		HTTP: &HTTPResult{
			Status:     StatusPass,
			StatusCode: 200,
			Timings: HTTPTiming{
				TTFB:  DurationMs(45600 * time.Microsecond),
				Total: DurationMs(100500 * time.Microsecond),
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSnapshotJSON(&buf, snap); err != nil {
		t.Fatalf("WriteSnapshotJSON failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	dnsMap := raw["dns"].(map[string]any)
	durVal, ok := dnsMap["duration_ms"].(float64)
	if !ok {
		t.Fatalf("duration_ms is not a float64: %v", dnsMap["duration_ms"])
	}

	if durVal > 10000 {
		t.Errorf("duration_ms appears to be serialized in nanoseconds (%v) instead of milliseconds", durVal)
	}
	if durVal < 100 || durVal > 150 {
		t.Errorf("expected duration_ms around 123.4, got %v", durVal)
	}
}

func TestSnapshot_EncodingBOMs(t *testing.T) {
	validJSON := []byte(`{"schema_version":1,"tool_version":"0.1.0","target":{"original":"https://example.com"},"overall_status":"PASS"}`)

	clean, err := decodeTextBytes(validJSON)
	if err != nil || !bytes.Equal(clean, validJSON) {
		t.Errorf("UTF-8 decoding mismatch")
	}

	utf8BOM := append([]byte("\xef\xbb\xbf"), validJSON...)
	clean, err = decodeTextBytes(utf8BOM)
	if err != nil || !bytes.Equal(clean, validJSON) {
		t.Errorf("UTF-8 BOM decoding failed")
	}

	var u16LE []byte
	u16LE = append(u16LE, 0xff, 0xfe)
	for _, b := range validJSON {
		u16LE = append(u16LE, b, 0x00)
	}
	clean, err = decodeTextBytes(u16LE)
	if err != nil || !bytes.Equal(clean, validJSON) {
		t.Errorf("UTF-16 LE decoding failed: %s", string(clean))
	}

	oddLE := append(u16LE, 0x12)
	_, err = decodeTextBytes(oddLE)
	if err == nil {
		t.Errorf("expected error for odd-length UTF-16, got nil")
	}
}

func TestSnapshot_SchemaValidation(t *testing.T) {
	futureSnap := `{"schema_version":999,"tool_version":"9.0.0","target":{"original":"https://example.com"},"overall_status":"PASS"}`
	tmpFile, err := os.CreateTemp("", "snap-*.json")
	if err != nil {
		t.Fatalf("temp file error: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, _ = tmpFile.Write([]byte(futureSnap))
	tmpFile.Close()

	_, err = LoadSnapshotFile(tmpFile.Name())
	if err == nil {
		t.Fatal("expected error on unsupported schema_version 999, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported snapshot schema version 999") {
		t.Errorf("expected message mentioning unsupported schema version, got: %v", err)
	}
}

func TestSnapshot_DiffOrderIndependence(t *testing.T) {
	s1 := &Snapshot{
		Target: TargetInfo{Original: "https://example.com"},
		DNS: &DNSResult{
			Status:    StatusPass,
			IPv4Addrs: []string{"192.0.2.1", "198.51.100.1"},
		},
		OverallStatus: StatusPass,
	}
	s2 := &Snapshot{
		Target: TargetInfo{Original: "https://example.com"},
		DNS: &DNSResult{
			Status:    StatusPass,
			IPv4Addrs: []string{"198.51.100.1", "192.0.2.1"},
		},
		OverallStatus: StatusPass,
	}

	diff := DiffSnapshots(s1, s2)
	if len(diff.Differences) != 0 {
		t.Errorf("expected 0 differences for reordered address lists, got: %+v", diff.Differences)
	}
}

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantHost   string
		wantPort   int
		wantScheme string
		wantTLS    bool
		wantHTTP   bool
		wantIsIP   bool
		wantErr    bool
	}{
		{
			name:       "standard https url",
			input:      "https://api.example.com",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantScheme: "https",
			wantTLS:    true,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "uppercase scheme and trailing dot",
			input:      "HTTPS://API.EXAMPLE.COM.",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantScheme: "https",
			wantTLS:    true,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "standard http url with path and query",
			input:      "http://example.com/api/v1?token=secret123",
			wantHost:   "example.com",
			wantPort:   80,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "https custom port",
			input:      "https://example.com:8443",
			wantHost:   "example.com",
			wantPort:   8443,
			wantScheme: "https",
			wantTLS:    true,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "bare host:port 443",
			input:      "example.com:443",
			wantHost:   "example.com",
			wantPort:   443,
			wantScheme: "https",
			wantTLS:    true,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "bare host:port 8080",
			input:      "example.com:8080",
			wantHost:   "example.com",
			wantPort:   8080,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "bare domain",
			input:      "example.com",
			wantHost:   "example.com",
			wantPort:   80,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   false,
		},
		{
			name:       "ipv4 address with port",
			input:      "127.0.0.1:8080",
			wantHost:   "127.0.0.1",
			wantPort:   8080,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   true,
		},
		{
			name:       "bare ipv4 address",
			input:      "1.1.1.1",
			wantHost:   "1.1.1.1",
			wantPort:   80,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   true,
		},
		{
			name:       "ipv6 with port",
			input:      "[2001:db8::1]:443",
			wantHost:   "2001:db8::1",
			wantPort:   443,
			wantScheme: "https",
			wantTLS:    true,
			wantHTTP:   true,
			wantIsIP:   true,
		},
		{
			name:       "bare ipv6",
			input:      "2001:db8::1",
			wantHost:   "2001:db8::1",
			wantPort:   80,
			wantScheme: "http",
			wantTLS:    false,
			wantHTTP:   true,
			wantIsIP:   true,
		},
		{
			name:    "unsupported ftp scheme",
			input:   "ftp://example.com/file",
			wantErr: true,
		},
		{
			name:    "empty target",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "example.com:999999",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}

			if res.Hostname != tt.wantHost {
				t.Errorf("Hostname = %q, want %q", res.Hostname, tt.wantHost)
			}
			if res.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", res.Port, tt.wantPort)
			}
			if res.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", res.Scheme, tt.wantScheme)
			}
			if res.UseTLS != tt.wantTLS {
				t.Errorf("UseTLS = %t, want %t", res.UseTLS, tt.wantTLS)
			}
			if res.UseHTTP != tt.wantHTTP {
				t.Errorf("UseHTTP = %t, want %t", res.UseHTTP, tt.wantHTTP)
			}
			if res.IsIP != tt.wantIsIP {
				t.Errorf("IsIP = %t, want %t", res.IsIP, tt.wantIsIP)
			}
		})
	}
}

func TestRedactHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization":       "Bearer super-secret-jwt-token-12345",
		"Proxy-Authorization": "Basic dXNlcjpwYXNz",
		"Cookie":              "session_id=abcdef123456",
		"Set-Cookie":          "session=xyz789; Secure; HttpOnly",
		"X-Api-Key":           "key-9999",
		"X-Auth-Token":        "token-secret",
		"Content-Type":        "application/json",
		"Server":              "nginx/1.24",
	}

	clean := RedactHeaders(headers)

	if clean["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization header not redacted: %s", clean["Authorization"])
	}
	if clean["Proxy-Authorization"] != "[REDACTED]" {
		t.Errorf("Proxy-Authorization header not redacted: %s", clean["Proxy-Authorization"])
	}
	if clean["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie header not redacted: %s", clean["Cookie"])
	}
	if clean["Set-Cookie"] != "[REDACTED]" {
		t.Errorf("Set-Cookie header not redacted: %s", clean["Set-Cookie"])
	}
	if clean["X-Api-Key"] != "[REDACTED]" {
		t.Errorf("X-Api-Key header not redacted: %s", clean["X-Api-Key"])
	}
	if clean["X-Auth-Token"] != "[REDACTED]" {
		t.Errorf("X-Auth-Token header not redacted: %s", clean["X-Auth-Token"])
	}
	if clean["Content-Type"] != "application/json" {
		t.Errorf("Content-Type altered: %s", clean["Content-Type"])
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "http://user:secretpass@proxy.corp.com:3128",
			want:  "http://***:***@proxy.corp.com:3128",
		},
		{
			input: "https://api.example.com/data?token=my_secret_token&user=alice",
			want:  "token=[REDACTED]",
		},
		{
			input: "https://api.example.com/v1?api_key=xyz&secret=abc",
			want:  "api_key=[REDACTED]",
		},
		{
			input: "https://api.example.com/v1?access_token=xyz&passwd=abc&session_id=123",
			want:  "access_token=[REDACTED]",
		},
	}

	for _, tt := range tests {
		got := RedactURL(tt.input)
		if !strings.Contains(got, tt.want) {
			t.Errorf("RedactURL(%q) = %q, want substring %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeTerminal(t *testing.T) {
	ansiStr := "\x1b[31;1mRed Alert\x1b[0m"
	cleaned := SanitizeTerminalOneLine(ansiStr)
	if cleaned != "Red Alert" {
		t.Errorf("SanitizeTerminalOneLine(%q) = %q, want 'Red Alert'", ansiStr, cleaned)
	}

	lineForgingStr := "First Line\r\nSecond Forged Line\tTab"
	oneLine := SanitizeTerminalOneLine(lineForgingStr)
	if strings.Contains(oneLine, "\n") || strings.Contains(oneLine, "\r") {
		t.Errorf("SanitizeTerminalOneLine contains newline characters: %q", oneLine)
	}
	if oneLine != "First Line  Second Forged Line Tab" {
		t.Errorf("SanitizeTerminalOneLine mismatch: %q", oneLine)
	}
}

func FuzzDNSMessageParser(f *testing.F) {
	f.Add([]byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
		93, 184, 216, 34,
	})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xC0, 0x00, 0xC0, 0x02})
	f.Add([]byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseDNSMessage(data)
	})
}

func FuzzDNSNameDecoder(f *testing.F) {
	f.Add([]byte{0x03, 'f', 'o', 'o', 0x03, 'b', 'a', 'r', 0x00}, 0)
	f.Add([]byte{0xC0, 0x00}, 0)
	f.Add([]byte{0x00}, 0)
	f.Add([]byte{0xC0, 0x02, 0x03, 'f', 'o', 'o', 0x00}, 0)

	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		_, _, _ = DecodeDomainName(data, offset)
	})
}

func TestNormalizeResolverAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:5353", "[2606:4700:4700::1111]:5353"},
		{"dns.google", "dns.google:53"},
		{"dns.google:853", "dns.google:853"},
	}

	for _, tt := range tests {
		got := normalizeResolverAddr(tt.input)
		if got != tt.want {
			t.Errorf("normalizeResolverAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNoHTTPMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Run(ctx, Options{
		Target: ts.URL,
		NoHTTP: true,
	})
	if err != nil {
		t.Fatalf("Run with NoHTTP failed: %v", err)
	}
	if res.HTTP != nil {
		t.Errorf("expected HTTP probe to be nil with NoHTTP=true, got %+v", res.HTTP)
	}
	if res.OverallStatus != StatusPass {
		t.Errorf("expected StatusPass, got %s", res.OverallStatus)
	}
}

func TestImpendingCertificateExpirationWarning(t *testing.T) {
	now := time.Now()
	res := &RunResult{
		OverallStatus: StatusPass,
		Target: TargetInfo{
			Hostname: "example.com",
			Port:     443,
			UseTLS:   true,
		},
		TLS: &TLSResult{
			Status:        StatusPass,
			Connected:     true,
			ExpiryValid:   true,
			HostnameValid: true,
			ChainValid:    true,
			NotBefore:     now.Add(-60 * 24 * time.Hour),
			NotAfter:      now.Add(10 * 24 * time.Hour),
			LeafSubject:   "CN=example.com",
			LeafIssuer:    "Let's Encrypt",
			ServerName:    "example.com",
		},
	}

	findings, _, _ := ExplainWithReasoning(res)
	var foundExpiryWarning bool
	for _, f := range findings {
		if f.Severity == SeverityWarning && strings.Contains(f.Title, "Expiring Soon") {
			foundExpiryWarning = true
			break
		}
	}
	if !foundExpiryWarning {
		t.Errorf("expected impending certificate expiry warning finding, findings: %+v", findings)
	}
}

func TestParallelMatrixExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	matrix, err := RunMatrix(ctx, MatrixOptions{
		Target:      ts.URL,
		Timeout:     3 * time.Second,
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunMatrix failed: %v", err)
	}

	if len(matrix.Paths) < 4 {
		t.Fatalf("expected at least 4 paths in matrix, got %d", len(matrix.Paths))
	}

	expectedPathNames := []string{"Application path", "Direct", "IPv4 direct", "IPv6 direct"}
	for i, name := range expectedPathNames {
		if matrix.Paths[i].Name != name {
			t.Errorf("matrix.Paths[%d].Name = %q, want %q", i, matrix.Paths[i].Name, name)
		}
	}
}
